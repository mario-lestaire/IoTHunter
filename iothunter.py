#!/usr/bin/env python3


import argparse
import nmap
from scapy.all import ARP, Ether, srp

# Puertos conocidos de dispositivos IoT
KNOWN_IOT_PORTS = [80, 443, 8888, 554, 5050]

# Vulnerabilidades conocidas
KNOWN_VULNERABILITIES = {
    22: "SSH abierto en el puerto 22 - Riesgo de acceso no autorizado si se usa una contraseña débil o predeterminada",
    23: "Telnet abierto en el puerto 23 - Protocolo no cifrado con riesgo de intercepción de credenciales",
    21: "FTP abierto en el puerto 21 - Riesgo de exposición de archivos y acceso no autorizado",
    139: "NetBIOS abierto en el puerto 139 - Riesgo de compartición de archivos y exposición de información",
    445: "Microsoft-DS abierto en el puerto 445 - Riesgo asociado a Samba/Windows, como el ransomware WannaCry",
    161: "SNMP abierto en el puerto 161 - Riesgo de recolección de información y configuración del dispositivo si se usa la comunidad por defecto",
    389: "LDAP abierto en el puerto 389 - Riesgo de exposición de directorios y credenciales si no está correctamente configurado",
    3306: "MySQL abierto en el puerto 3306 - Riesgo de acceso a bases de datos y manipulación de datos",
    1433: "MSSQL abierto en el puerto 1433 - Riesgo de acceso a bases de datos y manipulación de datos",
    5060: "SIP abierto en el puerto 5060 - Riesgo relacionado con sistemas de VoIP y comunicaciones",
    1883: "MQTT abierto en el puerto 1883 - Riesgo asociado a dispositivos IoT y comunicaciones M2M",
    9200: "Elasticsearch abierto en el puerto 9200 - Riesgo de exposición de datos y acceso no autorizado",
    11211: "Memcached abierto en el puerto 11211 - Riesgo de amplificación DDoS y exposición de datos",
    6379: "Redis abierto en el puerto 6379 - Riesgo de acceso no autorizado y exposición de datos",
    27017: "MongoDB abierto en el puerto 27017 - Riesgo de exposición de bases de datos y manipulación de datos"
}


def setup_arguments():
    parser = argparse.ArgumentParser(description="Detector de Dispositivos IoT Vulnerables")
    parser.add_argument("-r", "--range", default="192.168.1.0/24",
                        help="Especifica el rango IP a escanear, por defecto es 192.168.1.0/24")
    return parser.parse_args()

def scan_local_network(ip_range="192.168.1.0/24"):
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    result = srp(arp_packet, timeout=3, verbose=0)[0]
    active_hosts = [received.psrc for sent, received in result]
    return active_hosts

def identify_iot_devices(ip_list):
    nm = nmap.PortScanner()
    iot_devices = {}
    for ip in ip_list:
        nm.scan(hosts=ip, arguments='-T4 -F')
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto].keys():
                if port in KNOWN_IOT_PORTS:
                    device_info = nm[ip]['hostnames'][0]['name'] if nm[ip]['hostnames'] else "Unknown"
                    iot_devices[ip] = device_info
                    break
    return iot_devices

def evaluate_vulnerabilities(iot_dict):
    vulnerabilities = {}
    nm = nmap.PortScanner()
    for device, device_info in iot_dict.items():
        nm.scan(hosts=device, arguments='-T4 -p-')
        open_ports = [port for port in nm[device].all_tcp() if nm[device].tcp(port)['state'] == 'open']
        device_vulns = []
        for port in open_ports:
            if port in KNOWN_VULNERABILITIES:
                device_vulns.append(KNOWN_VULNERABILITIES[port])
        if device_vulns:
            vulnerabilities[device] = {
                "info": device_info,
                "vulnerabilities": device_vulns
            }
    return vulnerabilities

def main():
    args = setup_arguments()
    ip_range = args.range
    
    ip_list = scan_local_network(ip_range)
    iot_devices = identify_iot_devices(ip_list)
    vulnerabilities = evaluate_vulnerabilities(iot_devices)
    
    print("Dispositivos IoT detectados:", len(iot_devices))
    for device, data in vulnerabilities.items():
        print(f"Dispositivo: {device} ({data['info']}) - Vulnerabilidades: {', '.join(data['vulnerabilities'])}")

if __name__ == "__main__":
    main()
