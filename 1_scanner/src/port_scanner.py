import nmap


def scan_active_ports(host_ip: str, start_port: int, end_port: int):
    scanner = nmap.PortScanner()
    for port in range(start_port, end_port):
        res = scanner.scan(host_ip, str(port))
        state = res['scan'][host_ip]['tcp'][port]['state']
        print(f'port {port}: {state}')


if __name__ == '__main__':
    ip = input('Enter the remote host IP to scan: ')
    start_port = int(input('Enter the start port number: '))
    end_port = int(input('Enter the end port number: '))
    scan_active_ports(ip, start_port, end_port)
