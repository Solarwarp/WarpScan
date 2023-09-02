from scapy.all import ARP, Ether, srp
import socket


print("""
     _       __                _____                
    | |     / /___ __________ / ___/_________ _____ 
    | | /| / / __ `/ ___/ __ \\ __ \\/ ___/ __ `/ _ \\
    | |/ |/ / /_/ / /  / /_/ /__/ / /__/ /_/ / / / //
    |__/|__/\__,_/_/  / .___/____/\\___/\\__,_/_/ /_/ 
                     /_/                           
                By: SolarWarp
""")

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s.connect(("8.8.8.8", 80))

    local_ip = s.getsockname()[0]
    s.close()
    return local_ip

def get_network_range(ip_addr):
    # Assuming the network mask is 255.255.255.0 or /24
    ip_parts = ip_addr.split(".")
    return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1/24"

def scan(ip):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=ip)
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=False)[0]
    devices = []

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

local_ip = get_local_ip()
network = get_network_range(local_ip)

devices = scan(network)

print("Available devices in the network:")
print("IP Address\t\tMAC Address")
print("-----------------------------------------")
for device in devices:
    print(device['ip'] + "\t\t" + device['mac'])
