from scapy.all import sniff, conf, Packet, NetworkInterface, get_if_list
from typing import Optional, List

DEAFULT_INTERFACE: int = -1
def proccess_capture_packets(packet: Packet):
    '''This function handle captuerd packets'''
    print(packet.summary())

def start_sniffer(interface_name: str  = conf.iface):
    '''This function start sniffing by given interface'''
    print(f"Sniffing on {interface_name}")
    try:
        packets = sniff(iface=interface_name,prn=proccess_capture_packets)
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