from scapy.all import sniff, conf, Packet, PacketList,NetworkInterface, get_if_list, IP, TCP, Raw
from netaddr import IPNetwork, IPAddress
from typing import Optional, List

DEAFULT_INTERFACE: int = -1
LOOPBACK_ADDRESS: str = "0.0.0.0"
LOCAL_IP_ADDRESS_INDEX: int = 4
CANARY_SERVICE_RANGE = range(9000, 9011)
TCP_FLAGS = ['A' , 'S'] # ACK, SYN


class enum:
    ACK='A'

def is_local_ip(ip) -> bool:
    ''' This function checks if given ip belongs to local network '''
    local_networks = []

    for add in conf.route.routes:
        #if add != LOOPBACK_ADDRESS:
            # add network subnet to list
        local_networks.append(add[LOCAL_IP_ADDRESS_INDEX])

    for network in local_networks:
        #import ipdb; ipdb.set_trace()
        if IPAddress(ip) in IPNetwork(network):
            return True

    return False


def handle_sus_connection(packet: Packet):
    '''Handle suspicious connection'''
    print(f'Suspicious connection detected form [src_Ip = {packet[IP].src}:{packet[IP].sport}] to [dst_ip = {packet[IP].dst}:{packet[TCP].dport}]')
    print(f"Protocol: TCP/{packet[TCP].dport}")
    if packet.haslayer(Raw):
        data = packet[Raw].load.decode(errors="ignore")
        print(f'payload:\n{data}')


def proccess_capture_packets(packet: Packet):
    '''
        This function handle captuerd packets, and looks for packets includes
        IP belongs to our local network and have tco layer
    '''
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if is_local_ip(packet[IP].src) and (packet[TCP].dport in CANARY_SERVICE_RANGE):
            if (packet[TCP].flags == TCP_FLAGS[0] or packet[TCP].flags == TCP_FLAGS[1]):
                print('Captured TCP connection handshake ')

            handle_sus_connection(packet)





def start_sniffer(interface_name: str  = conf.iface):
    '''This function start sniffing by given interface'''
    print(f"Sniffing on {interface_name}")
    try:
        packets: PacketList = sniff(iface=interface_name,prn=proccess_capture_packets)
    except PermissionError:
        # in case we need sudo or run by admin
        print("Need admin privileges")
    except Exception as e:
        print(f"Sniffing error: {e}")



def get_desierd_interface() -> Optional[str]:
    '''This function prints all available interfaces and return user choice'''
    # get inetrafces into list
    interfaces: list[str] = get_if_list()
    if not interfaces:
        print("No interfaces found")
        return None

    print("interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"{i}: {interface}")

    choice = int(input("Select interface by number or -1 for defult interface:"))
    if choice is DEAFULT_INTERFACE:
        return conf.iface

    if 0 <= choice < len(interfaces):
        return interfaces[choice]
    else:
        print("Invalid choice")

    return None
def main():
    interface: str = get_desierd_interface()
    #print(interface)
    start_sniffer(interface)


if __name__ == "__main__":
    main()