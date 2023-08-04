from typing import Optional, List
import statistics
import time
import signal

from scapy.layers.inet import IP, ICMP, sr, sr1
import socket

should_stop = False


def keyboard_interrupt_handler(signal, frame):
    global should_stop
    should_stop = True


signal.signal(signal.SIGINT, keyboard_interrupt_handler)


def resolve_host(host: str) -> str:
    """
    :param host: host address as string
    :return: IPv4 address of the given host
    """
    ip = socket.gethostbyname(host)
    print(f'PING {host} ({ip}): 56 data bytes')
    return ip


def ping_for_ever(ip) -> List[Optional[float]]:
    """
    periodically sends icmp packets to the destination, until interrupted with CTRL+C
    :param ip: destination host which should be pinged
    :return:
    """
    global should_stop
    rtt_list = []
    while True:
        try:
            rtt = ping(ip, icmp_seq=len(rtt_list))
            rtt_list.append(rtt)
            time.sleep(0.1)
        except KeyboardInterrupt as e:
            break

        if should_stop:
            break

    return rtt_list


def ping(ip: str, icmp_seq: int = 0) -> Optional[float]:
    """
    sends 1 ICMP packet to the destination ip, and returns its rtt if available
    :param ip: name or ip address of destination host
    :param icmp_seq: icmp_seq identifier
    :return: rtt of received response [if exists else None]
    """
    icmp = IP(dst=ip) / ICMP()

    # print(f'Pinging {host}[{ip}] with {1} bytes of data')
    resp = sr1(icmp, timeout=10, verbose=False)
    if resp is None:
        print("Packet lost.")
        return None

    rtt = round(((resp.time - icmp.sent_time) * 1000), 3)
    print(f'{len(resp)} bytes from {resp.src}: icmp_seq={icmp_seq} ttl={resp.ttl} time={rtt}ms')
    return rtt


def print_statistics(rtt_list: List[float]):
    """
    prints statistics (min/avg/max/stddev rtt) of packets, and their loss ratio
    :param rtt_list: a list of rtt of each packet that is trasmitted. lost packets are represented with `None`
    :return: None
    """
    num_packets = len(rtt_list)
    num_lost = rtt_list.count(None)
    loss_ratio = int(num_lost / num_packets) * 100

    rtt_filtered = list(filter(lambda x: x is not None, rtt_list))
    rtt_min = round(min(rtt_filtered), 3)
    rtt_avg = round(statistics.mean(rtt_filtered), 3)
    rtt_max = round(max(rtt_filtered), 3)
    rtt_stdev = round(statistics.stdev(rtt_filtered), 3)

    print(f'--- {host} ping statistics ---')
    print(f'{num_packets} transmitted, {num_packets - num_lost} packets received, {loss_ratio}% packet loss')
    print(f'round-trip min/avg/max/stddev = {rtt_min}/{rtt_avg}/{rtt_max}/{rtt_stdev} ms')


if __name__ == '__main__':
    host = input('Please Enter Your IP/Domain: ')
    ip = resolve_host(host)
    rtt_list = ping_for_ever(ip)
    print_statistics(rtt_list)
