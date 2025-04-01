import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import netifaces
import re
from tqdm import tqdm
import urllib3
import ipaddress
import random

# Desactivar advertencias de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class EnhancedCameraScanner:
    def __init__(self):
        # Puertos ampliados para cámaras IP
        self.camera_ports = [
            80, 81, 82, 83, 84, 85, 86, 87, 88, 89,  # HTTP
            443, 444, 445, 446, 447, 448, 449,       # HTTPS
            554, 555, 556,                            # RTSP
            1935,                                     # RTMP
            37777, 37778, 37779,                      # Dahua
            8000, 8080, 8081, 8082, 8083, 8084, 8085, # Web interfaces
            8899, 8888,                               # Hikvision
            34567, 34568, 34569,                     # Otros fabricantes
            9000, 9001                                # ONVIF
        ]
        self.timeout = 2  # Reducido para escaneo más rápido
        self.threads = 100  # Más threads para escaneo más rápido
        self.open_cameras = []
        self.user_agents = [
            'Mozilla/5.0', 'curl/7.68.0', 'python-requests/2.25.1',
            'IP Camera Viewer', 'VLC/3.0.16', 'ONVIFDM'
        ]
        
        # Patrones para identificar cámaras
        self.camera_patterns = [
            r'<title>.*camera.*</title>',
            r'<title>.*webcam.*</title>',
            r'<title>.*surveillance.*</title>',
            r'<title>.*video.*</title>',
            r'<title>.*ip cam.*</title>',
            r'<title>.*dvr.*</title>',
            r'<title>.*nvr.*</title>',
            r'<title>.*hikvision.*</title>',
            r'<title>.*dahua.*</title>',
            r'<title>.*axis.*</title>',
            r'<title>.*foscam.*</title>'
        ]

    def get_all_networks(self):
        """Obtiene todas las redes locales posibles"""
        networks = []
        interfaces = netifaces.interfaces()
        
        for interface in interfaces:
            try:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        if 'addr' in addr_info and 'netmask' in addr_info:
                            ip = addr_info['addr']
                            if ip != '127.0.0.1':
                                netmask = addr_info['netmask']
                                network = self.calculate_network(ip, netmask)
                                if network and network not in networks:
                                    networks.append(network)
            except:
                continue
                
        return networks if networks else ['192.168.0.0/24', '10.0.0.0/24', '172.16.0.0/24']  # Defaults

    def calculate_network(self, ip, netmask):
        """Calcula la red a partir de IP y máscara"""
        try:
            ip_int = int.from_bytes(ipaddress.IPv4Address(ip).packed, 'big')
            mask_int = int.from_bytes(ipaddress.IPv4Address(netmask).packed, 'big')
            network_int = ip_int & mask_int
            network_addr = ipaddress.IPv4Address(network_int)
            prefix = bin(mask_int).count('1')
            return f"{network_addr}/{prefix}"
        except:
            return None

    def generate_random_ips(self, count=1000):
        """Genera IPs aleatorias en rangos comunes"""
        common_ranges = [
            ('192.168.0.0', '192.168.255.255'),
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255')
        ]
        
        ips = []
        for _ in range(count):
            net_range = random.choice(common_ranges)
            start_ip = ipaddress.IPv4Address(net_range[0])
            end_ip = ipaddress.IPv4Address(net_range[1])
            rand_ip = str(ipaddress.IPv4Address(random.randint(int(start_ip), int(end_ip))))
            ips.append(rand_ip)
            
        return ips

    def scan_port(self, ip_port_tuple):
        """Escanea un puerto específico en una IP optimizado"""
        ip, port = ip_port_tuple
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    s.shutdown(socket.SHUT_RDWR)
                    return ip, port, True
                return ip, port, False
        except:
            return ip, port, False

    def check_open_camera(self, ip, port):
        """Verifica si el dispositivo es una cámara con múltiples métodos"""
        # Intentar con diferentes protocolos
        protocols = []
        if port in [80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 8080, 8081, 8082, 8083, 8084, 8085, 8888, 8899]:
            protocols.append('http')
            protocols.append('https')  # Intentar ambos
        elif port in [443, 444, 445, 446, 447, 448, 449]:
            protocols.append('https')
        else:
            protocols.append('rtsp')
            protocols.append('rtmp')
            protocols.append('onvif')
        
        for protocol in protocols:
            try:
                url, test_urls = self.build_urls(protocol, ip, port)
                result = self.test_camera_urls(url, test_urls)
                if result[0]:
                    return result
            except:
                continue
                
        return False, None

    def build_urls(self, protocol, ip, port):
        """Construye URLs para probar según el protocolo"""
        base_url = f"{protocol}://{ip}"
        if (protocol == 'http' and port != 80) or (protocol == 'https' and port != 443):
            base_url += f":{port}"
            
        test_urls = []
        
        if protocol in ['http', 'https']:
            test_urls.extend([
                f"{base_url}/", 
                f"{base_url}/viewer/live/index.html",
                f"{base_url}/live/index.shtml",
                f"{base_url}/live.sdp",
                f"{base_url}/img/video.mjpeg",
                f"{base_url}/video/mjpg.cgi",
                f"{base_url}/axis-cgi/mjpg/video.cgi",
                f"{base_url}/cgi-bin/mjpg/video.cgi",
                f"{base_url}/nphMotionJpeg",
                f"{base_url}/mjpg/video.mjpg",
                f"{base_url}/cam/realmonitor",
                f"{base_url}/Streaming/Channels/101",
                f"{base_url}/onvif/device_service"
            ])
        elif protocol == 'rtsp':
            test_urls.extend([
                f"rtsp://{ip}:{port}/live.sdp",
                f"rtsp://{ip}:{port}/ch0_0.h264",
                f"rtsp://{ip}:{port}/cam/realmonitor",
                f"rtsp://{ip}:{port}/Streaming/Channels/101",
                f"rtsp://{ip}:{port}/h264stream"
            ])
        elif protocol == 'rtmp':
            test_urls.append(f"rtmp://{ip}:{port}/live")
        elif protocol == 'onvif':
            test_urls.append(f"http://{ip}:{port}/onvif/device_service")
            
        return base_url, test_urls

    def test_camera_urls(self, base_url, test_urls):
        """Prueba múltiples URLs para detectar cámaras"""
        headers = {'User-Agent': random.choice(self.user_agents)}
        
        # Probar la URL base primero
        try:
            response = requests.get(base_url, timeout=self.timeout, verify=False, headers=headers)
            if response.status_code == 200 and self.is_camera(response, base_url):
                return True, base_url
        except:
            pass
            
        # Probar todas las URLs específicas
        for url in test_urls:
            try:
                response = requests.get(url, timeout=self.timeout, verify=False, headers=headers)
                
                # Verificar por código de estado y tipo de contenido
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    # Si es un flujo de video/imagen
                    if any(x in content_type for x in ['image', 'video', 'mjpeg', 'mpeg', 'h264']):
                        return True, url
                        
                    # Si el contenido HTML parece de cámara
                    if self.is_camera(response, url):
                        return True, url
                        
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:  # Requiere autenticación
                    # Pero podría ser una cámara con login por defecto
                    if self.looks_like_camera_url(url):
                        return True, url
            except:
                continue
                
        return False, None

    def is_camera(self, response, url):
        """Determina si el dispositivo es una cámara con múltiples métodos"""
        content = response.text.lower()
        
        # Verificar patrones en el contenido HTML
        if any(re.search(pattern, content) for pattern in self.camera_patterns):
            return True
            
        # Verificar en URL
        if any(keyword in url.lower() for keyword in ['cam', 'video', 'stream', 'live', 'mjpg', 'mpeg']):
            return True
            
        # Verificar encabezados
        server_header = response.headers.get('Server', '').lower()
        if any(brand in server_header for brand in ['dahua', 'hikvision', 'axis', 'foscam']):
            return True
            
        # Verificar favicon (algunas cámaras tienen favicon único)
        if 'favicon.ico' in content:
            try:
                favicon_url = f"{url.split('//')[0]}//{url.split('//')[1].split('/')[0]}/favicon.ico"
                favicon_res = requests.get(favicon_url, timeout=self.timeout, verify=False)
                if favicon_res.status_code == 200:
                    if len(favicon_res.content) > 100:  # Favicons de cámara suelen ser más grandes
                        return True
            except:
                pass
                
        return False

    def looks_like_camera_url(self, url):
        """Determina si una URL parece ser de cámara por su estructura"""
        patterns = [
            r'.*/live\.sdp$',
            r'.*/video\.mjpg$',
            r'.*/mjpg/video\.cgi$',
            r'.*cam/realmonitor$',
            r'.*Streaming/Channels/\d+$'
        ]
        return any(re.search(pattern, url.lower()) for pattern in patterns)

    def scan_network_range(self, network):
        """Escanea un rango de red específico"""
        print(f"\n[+] Escaneando red {network}")
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            ips_to_scan = [str(host) for host in net.hosts()]
        except:
            print(f"[-] Red inválida: {network}")
            return
            
        # Escanear puertos en todas las IPs
        ip_port_combinations = [(ip, port) for ip in ips_to_scan for port in self.camera_ports]
        
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_port, ip_port) for ip_port in ip_port_combinations]
            
            for future in tqdm(as_completed(futures), total=len(ip_port_combinations), 
                              desc=f"Escaneando {network}", unit="ports"):
                ip, port, is_open = future.result()
                if is_open:
                    open_ports.append((ip, port))
        
        # Verificar cámaras en puertos abiertos
        if open_ports:
            print(f"[+] {len(open_ports)} puertos abiertos encontrados en {network}")
            cameras_found = 0
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for ip, port in open_ports:
                    futures.append(executor.submit(self.check_open_camera, ip, port))
                
                for future in tqdm(as_completed(futures), total=len(open_ports), 
                                  desc="Verificando cámaras", unit="dispositivos"):
                    is_camera, access_url = future.result()
                    if is_camera and access_url:
                        self.open_cameras.append((ip, port, access_url))
                        print(f"\n[!] Cámara encontrada: {access_url}")
                        cameras_found += 1
            
            # Mensaje específico cuando hay puertos abiertos pero no son cámaras
            if cameras_found == 0:
                print(f"\n[i] No se encontraron cámaras accesibles en {network} (aunque se detectaron {len(open_ports)} puertos abiertos)")
        else:
            print(f"\n[-] No se encontraron puertos abiertos en {network} (ningún dispositivo respondió en los puertos comunes de cámaras)")

    def scan_random_ips(self, count=1000):
        """Escanea un conjunto de IPs aleatorias"""
        print(f"\n[+] Escaneando {count} IPs aleatorias...")
        random_ips = self.generate_random_ips(count)
        
        ip_port_combinations = [(ip, port) for ip in random_ips for port in self.camera_ports]
        
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_port, ip_port) for ip_port in ip_port_combinations]
            
            for future in tqdm(as_completed(futures), total=len(ip_port_combinations), 
                              desc="Escaneando IPs aleatorias", unit="ports"):
                ip, port, is_open = future.result()
                if is_open:
                    open_ports.append((ip, port))
        
        # Verificar cámaras en puertos abiertos
        if open_ports:
            print(f"[+] {len(open_ports)} puertos abiertos encontrados en IPs aleatorias")
            cameras_found = 0
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for ip, port in open_ports:
                    futures.append(executor.submit(self.check_open_camera, ip, port))
                
                for future in tqdm(as_completed(futures), total=len(open_ports), 
                                  desc="Verificando cámaras", unit="dispositivos"):
                    is_camera, access_url = future.result()
                    if is_camera and access_url:
                        self.open_cameras.append((ip, port, access_url))
                        print(f"\n[!] Cámara encontrada: {access_url}")
                        cameras_found += 1
            
            if cameras_found == 0:
                print(f"\n[i] No se encontraron cámaras accesibles en las IPs aleatorias (aunque se detectaron {len(open_ports)} puertos abiertos)")
        else:
            print("\n[-] No se encontraron puertos abiertos en las IPs aleatorias")

    def display_results(self):
        """Muestra los resultados del escaneo"""
        if not self.open_cameras:
            print("\nNo se encontraron cámaras con acceso público.")
            return
        
        print("\n[!] Cámaras con acceso público encontradas:")
        for ip, port, access_url in self.open_cameras:
            print(f"\nIP: {ip}")
            print(f"Puerto: {port}")
            print(f"URL de acceso: {access_url}")
            print("Posible vulnerabilidad: Acceso público sin autenticación")
            
        print("\n[!] ADVERTENCIA: Estas cámaras son accesibles sin autenticación.")
        print("    Se recomienda protegerlas inmediatamente con contraseña segura.")

def main():
    print("""
    #############################################
    # Escáner Avanzado de Cámaras IP           #
    # (Solo para uso ético y legal)            #
    #############################################
    """)
    
    scanner = EnhancedCameraScanner()
    
    # Escanear todas las redes locales
    networks = scanner.get_all_networks()
    for network in networks:
        scanner.scan_network_range(network)
    
    # Escanear IPs aleatorias para mayor cobertura
    scanner.scan_random_ips(count=2000)
    
    # Mostrar resultados finales
    scanner.display_results()

if __name__ == "__main__":
    main()
