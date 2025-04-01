import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import netifaces
import re
from tqdm import tqdm
import urllib3
import ipaddress
import random
from typing import Optional, List, Tuple, Dict

# Desactivar advertencias de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class StealthCameraScanner:
    def __init__(self, proxy_config: Optional[Dict] = None):
        # Configuración de proxy
        self.proxy_config = proxy_config
        self.proxy_working = False
        self.proxy_verified = False
        
        # Puertos para cámaras IP
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
        self.timeout = 3 if not proxy_config else 5  # Más tiempo para proxies
        self.threads = 50 if not proxy_config else 20  # Menos hilos para proxies
        self.open_cameras = []
        
        # Configuración de User-Agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'python-requests/2.25.1',
            'curl/7.68.0',
            'IP Camera Viewer/2.8.6',
            'VLC/3.0.16 LibVLC/3.0.16'
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

    def verify_proxy(self) -> bool:
        """Verifica si el proxy está funcionando correctamente"""
        if not self.proxy_config or self.proxy_verified:
            return self.proxy_working
            
        test_url = "http://httpbin.org/ip"
        try:
            response = requests.get(
                test_url,
                proxies=self.proxy_config,
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                origin_ip = response.json().get('origin', '')
                print(f"\n[i] Proxy funcionando correctamente. IP de origen: {origin_ip}")
                self.proxy_working = True
            else:
                print("\n[!] Proxy configurado pero no respondió correctamente")
                self.proxy_working = False
                
        except Exception as e:
            print(f"\n[!] Error al verificar proxy: {str(e)}")
            self.proxy_working = False
            
        self.proxy_verified = True
        return self.proxy_working

    def make_request(self, url: str, headers: Dict = None) -> Optional[requests.Response]:
        """Realiza una solicitud HTTP con o sin proxy"""
        if headers is None:
            headers = {'User-Agent': random.choice(self.user_agents)}
            
        try:
            if self.proxy_config and self.proxy_working:
                response = requests.get(
                    url,
                    headers=headers,
                    proxies=self.proxy_config,
                    timeout=self.timeout,
                    verify=False
                )
            else:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False
                )
            return response
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Error en la solicitud a {url}: {str(e)}")
            return None
        except Exception as e:
            print(f"\n[!] Error inesperado: {str(e)}")
            return None

    def get_all_networks(self) -> List[str]:
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
                
        return networks if networks else ['192.168.0.0/24', '10.0.0.0/24', '172.16.0.0/24']

    def calculate_network(self, ip: str, netmask: str) -> Optional[str]:
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

    def generate_random_ips(self, count: int = 1000) -> List[str]:
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

    def scan_port(self, ip_port_tuple: Tuple[str, int]) -> Tuple[str, int, bool]:
        """Escanea un puerto específico en una IP"""
        ip, port = ip_port_tuple
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    s.shutdown(socket.SHUT_RDWR)
                    return (ip, port, True)
                return (ip, port, False)
        except:
            return (ip, port, False)

    def check_open_camera(self, ip: str, port: int) -> Tuple[bool, Optional[str]]:
        """Verifica si el dispositivo es una cámara con múltiples métodos"""
        protocols = []
        if port in [80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 8080, 8081, 8082, 8083, 8084, 8085, 8888, 8899]:
            protocols.append('http')
            protocols.append('https')
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
                
        return (False, None)

    def build_urls(self, protocol: str, ip: str, port: int) -> Tuple[str, List[str]]:
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
            
        return (base_url, test_urls)

    def test_camera_urls(self, base_url: str, test_urls: List[str]) -> Tuple[bool, Optional[str]]:
        """Prueba múltiples URLs para detectar cámaras"""
        headers = {'User-Agent': random.choice(self.user_agents)}
        
        # Probar la URL base primero
        try:
            response = self.make_request(base_url, headers)
            
            if response and response.status_code == 200 and self.is_camera(response, base_url):
                return (True, base_url)
        except:
            pass
            
        # Probar todas las URLs específicas
        for url in test_urls:
            try:
                response = self.make_request(url, headers)
                
                if not response:
                    continue
                    
                # Verificar por código de estado y tipo de contenido
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    # Si es un flujo de video/imagen
                    if any(x in content_type for x in ['image', 'video', 'mjpeg', 'mpeg', 'h264']):
                        return (True, url)
                        
                    # Si el contenido HTML parece de cámara
                    if self.is_camera(response, url):
                        return (True, url)
                        
            except requests.exceptions.HTTPError as e:
                if hasattr(e, 'response') and e.response.status_code == 401:
                    if self.looks_like_camera_url(url):
                        return (True, url)
            except:
                continue
                
        return (False, None)

    def is_camera(self, response: requests.Response, url: str) -> bool:
        """Determina si el dispositivo es una cámara con múltiples métodos"""
        try:
            content = response.text.lower()
        except:
            return False
        
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
            
        return False

    def looks_like_camera_url(self, url: str) -> bool:
        """Determina si una URL parece ser de cámara por su estructura"""
        patterns = [
            r'.*/live\.sdp$',
            r'.*/video\.mjpg$',
            r'.*/mjpg/video\.cgi$',
            r'.*cam/realmonitor$',
            r'.*Streaming/Channels/\d+$'
        ]
        return any(re.search(pattern, url.lower()) for pattern in patterns)

    def scan_network_range(self, network: str):
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
            print(f"\n[-] No se encontraron puertos abiertos en {network}")

    def scan_random_ips(self, count: int = 1000):
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

def get_proxy_config() -> Optional[Dict]:
    """Obtiene la configuración del proxy del usuario"""
    proxy_types = {
        '1': 'http',
        '2': 'https',
        '3': 'socks4',
        '4': 'socks5'
    }
    
    print("\nConfiguración de Proxy:")
    print("1. HTTP")
    print("2. HTTPS")
    print("3. SOCKS4")
    print("4. SOCKS5")
    
    proxy_type = input("Seleccione el tipo de proxy (1-4): ")
    if proxy_type not in proxy_types:
        print("[-] Opción inválida. Continuando sin proxy.")
        return None
    
    proxy_host = input("Dirección del proxy (ej: 192.168.1.100 o proxy.example.com): ")
    proxy_port = input("Puerto del proxy (ej: 8080): ")
    proxy_user = input("Usuario (dejar vacío si no requiere autenticación): ")
    proxy_pass = input("Contraseña (dejar vacío si no requiere autenticación): ")
    
    proxy_url = f"{proxy_types[proxy_type]}://"
    
    if proxy_user and proxy_pass:
        proxy_url += f"{proxy_user}:{proxy_pass}@"
    
    proxy_url += f"{proxy_host}:{proxy_port}"
    
    return {
        'http': proxy_url,
        'https': proxy_url
    }

def main():
    print("""
    #############################################
    # Escáner Avanzado de Cámaras IP           #
    # (Solo para uso ético y legal)            #
    #############################################
    """)
    
    # Configuración de Proxy
    use_proxy = input("¿Usar proxy para enmascarar el escaneo? (s/n): ").lower() == 's'
    proxy_config = None
    
    if use_proxy:
        proxy_config = get_proxy_config()
    
    scanner = StealthCameraScanner(proxy_config=proxy_config)
    
    # Verificar proxy si está configurado
    if proxy_config:
        print("\n[i] Verificando conexión proxy...")
        if not scanner.verify_proxy():
            print("\n[!] El proxy no está funcionando correctamente. Continuando sin proxy.")
    
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
