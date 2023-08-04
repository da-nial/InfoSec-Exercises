from typing import List
import nmap

from ipaddress import IPv4Address


def generate_ips_in_range(start_ip: str, end_ip: str) -> List[str]:
    start_ip, end_ip = IPv4Address(start_ip), IPv4Address(end_ip)
    start_ip_int, end_ip_int = int(start_ip), int(end_ip)

    return [str(IPv4Address(ip_int)) for ip_int in range(start_ip_int, end_ip_int)]


def scan_active_hosts(start_ip: str, end_ip: str):
    ips_in_range = generate_ips_in_range(start_ip, end_ip)
    scanner = nmap.PortScanner()
    for ip in ips_in_range:
        res = scanner.scan(ip, arguments="-sP")
        state = res.get('scan', {}).get(ip, {}).get('status', {}).get('state', 'down')
        print(f'{ip} --> {state}')


if __name__ == '__main__':
    start_ip = input('Enter the start ip: ')
    end_ip = input('Enter the end ip: ')

    scan_active_hosts(start_ip, end_ip)
