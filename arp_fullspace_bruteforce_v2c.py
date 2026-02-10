
#pre-req:
#sudo apt update
#sudo apt install tcpreplay


#!/usr/bin/env python3
# arp_fullspace_bruteforce.py

import os
import subprocess
import time
import threading
from multiprocessing import Process, Event, cpu_count

from scapy.all import Ether, ARP, sendp, sniff

try:
    from scapy.all import sendpfast
    HAS_SENDPFAST = True
except ImportError:
    HAS_SENDPFAST = False

IFACE = "enp3s0"

PRIORITY_OCTETS = [10, 192, 172, 100, 169]
SKIP_OCTETS = set([0, 127]) | set(range(224, 256))

BATCH_SIZE = 4096

STATE_FILE = "/root/arp_fullspace_scanned.txt"

stop_event = Event()
found_result = {"ip": None, "mac": None}

BROADCAST_ETHER = Ether(dst="ff:ff:ff:ff:ff:ff")


def run_cmd(cmd):
    subprocess.run(cmd, shell=True, check=True)


def apply_kernel_tuning():
    tunables = [
        "net.ipv4.neigh.default.gc_thresh1=4096",
        "net.ipv4.neigh.default.gc_thresh2=8192",
        "net.ipv4.neigh.default.gc_thresh3=16384",
        "net.ipv4.conf.all.arp_accept=1",
        "net.ipv4.conf.all.arp_announce=2",
        f"net.ipv4.conf.{IFACE}.arp_filter=0",
        f"net.ipv4.conf.{IFACE}.rp_filter=0",
        f"net.ipv6.conf.{IFACE}.disable_ipv6=1",
    ]
    for t in tunables:
        run_cmd(f"sysctl -w {t}")


def apply_iface_tuning():
    run_cmd(f"ip link set {IFACE} txqueuelen 20000")
    for feat in ["gro", "gso", "tso", "lro"]:
        try:
            run_cmd(f"ethtool -K {IFACE} {feat} off")
        except subprocess.CalledProcessError:
            pass


def set_ip_for_octet(x):
    ip = f"{x}.0.0.7"
    run_cmd(f"ip addr flush dev {IFACE}")
    run_cmd(f"ip addr add {ip}/8 dev {IFACE}")
    run_cmd(f"ip link set {IFACE} up")
    run_cmd(f"ip neigh flush dev {IFACE}")
    return ip


def handle_reply(pkt):
    if ARP in pkt and pkt[ARP].op == 2:
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if not stop_event.is_set():
            found_result["ip"] = ip
            found_result["mac"] = mac
            print(f"[!] Discovered host: {ip}  MAC: {mac}")
            stop_event.set()


def sniffer():
    sniff(
        iface=IFACE,
        filter="arp and arp[6:2] = 2",
        prn=handle_reply,
        store=False,
        stop_filter=lambda p: stop_event.is_set(),
    )


def send_batch(batch):
    if not batch:
        return
    if HAS_SENDPFAST:
        sendpfast(batch, iface=IFACE, pps=1000000)
    else:
        sendp(batch, iface=IFACE, verbose=False)


def worker_sender(x, our_ip, start_a, end_a):
    batch = []
    for a in range(start_a, end_a):
        if stop_event.is_set():
            break
        for b in range(256):
            if stop_event.is_set():
                break
            for c in range(1, 255):
                if stop_event.is_set():
                    break

                target = f"{x}.{a}.{b}.{c}"
                pkt = BROADCAST_ETHER / ARP(op=1, psrc=our_ip, pdst=target)
                batch.append(pkt)

                if len(batch) >= BATCH_SIZE:
                    send_batch(batch)
                    batch = []

    if batch and not stop_event.is_set():
        send_batch(batch)


def sender_for_octet_parallel(x, our_ip):
    n_workers = cpu_count() or 1
    if n_workers > 256:
        n_workers = 256

    chunk = 256 // n_workers
    ranges = []
    start = 0
    for i in range(n_workers):
        end = start + chunk
        if i == n_workers - 1:
            end = 256
        ranges.append((start, end))
        start = end

    procs = []
    for (start_a, end_a) in ranges:
        p = Process(target=worker_sender, args=(x, our_ip, start_a, end_a))
        p.start()
        procs.append(p)

    for p in procs:
        p.join()


def scan_octet(x, idx, total):
    print(f"\n=== [{idx}/{total}] Scanning {x}.0.0.0/8 ===")

    start_time = time.time()

    our_ip = set_ip_for_octet(x)

    stop_event.clear()
    sniff_thread = threading.Thread(target=sniffer, daemon=True)
    sniff_thread.start()

    #sender_for_octet_parallel(x, our_ip)
    
    subprocess.run(["./arpblast_mt", IFACE, str(x), str(cpu_count()), "64"],check=True)

    duration = time.time() - start_time
    print(f"[✓] Completed {x}.0.0.0/8 in {duration:.1f} seconds using {cpu_count()} workers")


def build_scan_order():
    all_octets = list(range(1, 255))
    usable = [x for x in all_octets if x not in SKIP_OCTETS]
    remaining = [x for x in usable if x not in PRIORITY_OCTETS]
    return PRIORITY_OCTETS + remaining


def load_completed_octets():
    completed = set()
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            for line in f:
                try:
                    completed.add(int(line.strip()))
                except:
                    pass
    return completed


def mark_octet_completed(x):
    with open(STATE_FILE, "a") as f:
        f.write(f"{x}\n")


def main():
    if os.geteuid() != 0:
        print("Run as root")
        return

    apply_kernel_tuning()
    apply_iface_tuning()

    scan_order = build_scan_order()
    completed = load_completed_octets()
    scan_order = [x for x in scan_order if x not in completed]

    total = len(scan_order)

    print(f"[*] Remaining /8s to scan: {total}")
    print(f"[*] Using {cpu_count()} workers per /8")

    global_start = time.time()

    for idx, x in enumerate(scan_order, start=1):
        if stop_event.is_set():
            break
        try:
            scan_octet(x, idx, total)
            mark_octet_completed(x)
        except subprocess.CalledProcessError as e:
            print(f"[!] Command failed: {e}")
        if stop_event.is_set():
            break

    elapsed = time.time() - global_start

    if found_result["ip"]:
        print(f"[✓] Final result: {found_result['ip']}  MAC: {found_result['mac']}")
    else:
        print("[×] No host discovered")

    print(f"[*] Total elapsed time: {elapsed/3600:.2f} hours")


if __name__ == "__main__":
    main()
