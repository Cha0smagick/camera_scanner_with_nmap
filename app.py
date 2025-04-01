import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import netifaces
import re
from tqdm import tqdm
import urllib3

# Desactivar advertencias de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OpenCameraScanner:
    def __init__(self):
        self.camera_ports = [80, 81, 443, 554, 37777, 8000, 8080, 8081]
        self.timeout = 3
        self.threads = 50
        self.open_cameras = []

    def get_local_network(self):
        """Obtiene la red local a la que está conectada la máquina"""
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr_info in addrs[netifaces.AF_INET]:
                    if 'addr' in addr_info and 'netmask' in addr_info:
                        ip = addr_info['addr']
                        if ip != '127.0.0.1':
                            netmask = addr_info['netmask']
                            network = '.'.join(ip.split('.')[:3])
                            return f"{network}.0/24"
        return None

    def scan_port(self, ip_port_tuple):
        """Escanea un puerto específico en una IP"""
        ip, port = ip_port_tuple
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                return ip, port, result == 0
        except:
            return ip, port, False

    def check_open_camera(self, ip, port):
        """Verifica si el dispositivo es una cámara con acceso público"""
        protocols = ['http', 'https'] if port in [80, 443, 8080, 8081] else ['rtsp']
        
        for protocol in protocols:
            try:
                if protocol == 'http':
                    url = f"http://{ip}:{port}"
                elif protocol == 'https':
                    url = f"https://{ip}:{port}" if port != 443 else f"https://{ip}"
                else:
                    url = f"rtsp://{ip}:{port}/live.sdp"
                
                # Primera verificación - ¿Responde sin autenticación?
                response = requests.get(url, timeout=self.timeout, verify=False)
                
                # Si no hay redirección a login (código 200)
                if response.status_code == 200:
                    # Verificar si es una cámara
                    if self.is_camera(response, url):
                        return True, url
                
                # Segunda verificación - ¿Tiene recursos públicos?
                common_paths = [
                    'live.sdp', 'streaming/channels/1', 'img/video.mjpeg',
                    'video', 'mjpg/video.mjpg', 'cam/realmonitor'
                ]
                
                for path in common_paths:
                    test_url = f"{url}/{path}" if not url.endswith(path) else url
                    try:
                        test_response = requests.get(test_url, timeout=self.timeout, verify=False)
                        if test_response.status_code == 200:
                            if 'image' in test_response.headers.get('Content-Type', '') or \
                               'video' in test_response.headers.get('Content-Type', ''):
                                return True, test_url
                    except:
                        continue
                        
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:  # Requiere autenticación
                    return False, None
            except:
                continue
        
        return False, None

    def is_camera(self, response, url):
        """Determina si el dispositivo es una cámara"""
        content = response.text.lower()
        
        # Indicadores comunes en cámaras
        camera_indicators = [
            'camera', 'webcam', 'surveillance', 'video feed',
            'mjpg', 'm-jpeg', 'videostream', 'ip camera'
        ]
        
        # Verificar en contenido HTML
        if any(indicator in content for indicator in camera_indicators):
            return True
        
        # Verificar en URL
        if any(indicator in url.lower() for indicator in camera_indicators):
            return True
        
        # Verificar encabezados
        content_type = response.headers.get('Content-Type', '').lower()
        if 'image' in content_type or 'video' in content_type:
            return True
            
        return False

    def scan_network(self):
        """Escanea la red en busca de cámaras abiertas"""
        network = self.get_local_network()
        if not network:
            print("No se pudo determinar la red local.")
            return
        
        base_ip = '.'.join(network.split('.')[:3])
        ips_to_scan = [f"{base_ip}.{i}" for i in range(1, 255)]
        
        print(f"\nEscaneando red {network} en busca de cámaras abiertas...")
        
        # Primero escaneamos todos los puertos en todas las IPs
        print("\n[+] Escaneando puertos...")
        ip_port_combinations = [(ip, port) for ip in ips_to_scan for port in self.camera_ports]
        
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_port, ip_port) for ip_port in ip_port_combinations]
            
            for future in tqdm(as_completed(futures), total=len(ip_port_combinations), desc="Escaneo de puertos"):
                ip, port, is_open = future.result()
                if is_open:
                    open_ports.append((ip, port))
        
        if not open_ports:
            print("\nNo se encontraron puertos abiertos en dispositivos de red.")
            return
        
        # Luego verificamos cuáles son cámaras abiertas
        print("\n[+] Verificando cámaras abiertas...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.check_open_camera, ip, port) for ip, port in open_ports]
            
            for future in tqdm(as_completed(futures), total=len(open_ports), desc="Verificando cámaras"):
                is_camera, access_url = future.result()
                if is_camera and access_url:
                    self.open_cameras.append((future.ip, future.port, access_url))
        
        # Mostrar resultados
        self.display_results()

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
            print(f"Posible vulnerabilidad: Acceso público sin autenticación")
            
        print("\n[!] ADVERTENCIA: Estas cámaras son accesibles sin autenticación.")
        print("    Se recomienda protegerlas inmediatamente con contraseña segura.")

def main():
    print("""
    #############################################
    # Escáner de Cámaras con Acceso Público    #
    # (Solo para uso ético y legal)            #
    #############################################
    """)
    
    scanner = OpenCameraScanner()
    scanner.scan_network()

if __name__ == "__main__":
    main()
