# Network sniffer / packet sniffer
from scapy.all import sniff, wrpcap
import netifaces

# Function for finding all networks
def find_all_networks():
    interfaces = netifaces.interfaces() # Get a list of available network interfaces

    interfaces_list = []

    for interface in interfaces:
        interface_info = {
            'name': interface,
            'ip': netifaces.ifaddresses(interface).get(netifaces.AF_INET, [{'addr': 'No IP'}])[0]['addr'],
        }
        interfaces_list.append(interface_info)
    
    return interfaces_list 

# Capturing packets and saving them to a file
def packet_capturing(packet):
    captured_packets

    captured_packets.append(packet)  # Add the captured packet to the list

    if len(captured_packets) >= 50:
        wrpcap("packets.pcap", captured_packets)  # Save the captured packets to a pcap file
    print("Packets captured and saved successfully.")

if __name__ == "__main__":
    networks = find_all_networks()

    # Checking availability of the networks
    if len(networks) > 0:
        print("Networks Found :)")
        for network in networks:
            print(network)

        # Which interface user wants to use from the available interfaces
        select_iface = input("Enter the interface: ")
        select_filtering = input("Enter the filter (tcp/udp): ")

        # Initialize the list to store captured packets
        captured_packets = []

        # Network sniff
        sniff(iface=select_iface, filter=select_filtering, prn=packet_capturing)

    else:
        print("No Network Found :(")
