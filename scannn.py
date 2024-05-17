import nmap
from scapy.all import *

def scan_network(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sV')
    for host in nm.all_hosts():
        print(f'Host: {host}')
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = nm[host][proto][port]['name']
                print(f'Port: {port}\tState: {nm[host][proto][port]["state"]}\tService: {service}')
                check_vulnerabilities(host, port, service)

def packet_callback(packet):
    if packet.haslayer(TCP):
        if packet[TCP].dport == 80:
            print(f'HTTP Request Detected: {packet[IP].src} -> {packet[IP].dst}')
    elif packet.haslayer(DNS):
        print(f'DNS Query Detected: {packet[IP].src} -> {packet[IP].dst} : {packet[DNSQR].qname}')

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_callback, store=0)

def check_vulnerabilities(host, port, service):
    if service == 'http':
        print(f'Checking for HTTP vulnerabilities on {host}:{port}...')
        # Thêm mã kiểm tra lỗ hổng HTTP ở đây
    elif service == 'dns':
        print(f'Checking for DNS vulnerabilities on {host}:{port}...')
        # Thêm mã kiểm tra lỗ hổng DNS ở đây

if __name__ == "__main__":
    network = '192.168.1.0/24'  # Thay đổi địa chỉ mạng theo yêu cầu của bạn
    interface = 'eth0'  # Thay đổi tên interface theo yêu cầu của bạn
    print('Scanning network...')
    scan_network(network)
    print('Starting packet sniffing...')
    start_sniffing(interface)
