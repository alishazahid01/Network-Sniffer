# Network-Sniffer
Network Sniffer / Packet Sniffer Documentation
The "Network Sniffer / Packet Sniffer" script provides basic packet sniffing capabilities, allowing users to capture network packets on a specific network interface. This documentation outlines the functionality, usage, and key aspects of the script.
Purpose:
Packet sniffers are tools used for capturing and analyzing network traffic. They are valuable for diagnosing network issues, monitoring network activity, and understanding the data transmitted over a network. This script acts as a simple packet sniffer, capturing packets and saving them to a pcap file for analysis.
Code Structure and Functionality:
    1. find_all_networks Function:
        ◦ This function uses the netifaces library to find and list all available network interfaces along with their IP addresses.
        ◦ It returns a list of dictionaries containing the interface names and their corresponding IP addresses (or "No IP" if no IP is available).
    2. Packet Capturing and Storage (packet_capturing Function):
        ◦ The packet_capturing function is responsible for capturing network packets using the sniff function from the scapy library.
        ◦ Captured packets are stored in a list (captured_packets).
        ◦ When the number of captured packets reaches 50 (as specified), the function saves them to a pcap file named packets.pcap.
Usage:
    1. Network Interface Selection:
        ◦ Run the script. It will list all available network interfaces and their IP addresses.
        ◦ Enter the name of the network interface you want to use for packet capturing.
    2. Packet Capturing:
        ◦ The script will start capturing network packets on the selected interface.
        ◦ It will capture packets based on the specified filter (TCP, UDP, etc.) until 50 packets are captured.
        ◦ Captured packets are saved to packets.pcap.
Notes:
    • Customization: The script allows users to specify a filter for capturing specific types of packets (e.g., TCP, UDP). Modify the select_filtering variable to customize the packet capture.
    • Resource Limitation: This script captures a limited number of packets (50 in this case) for demonstration purposes. In real-world scenarios, you might want to capture a larger number of packets to perform in-depth analysis.
    • Permissions: Ensure that the script has the necessary permissions to capture network packets on the selected interface. Running the script with administrative privileges may be required on certain operating systems.
    • Analysis Tools: Use pcap analysis tools like Wireshark to open the generated packets.pcap file and perform detailed analysis of the captured network traffic.
    • Security and Privacy: Exercise caution and ensure legal and ethical use of packet sniffing tools. Unauthorized interception of network traffic is illegal and unethical.
This script serves as a basic example of packet sniffing capabilities. For more advanced and specific use cases, consider integrating additional filters, analysis methods, and real-time monitoring features. Always adhere to legal and ethical standards when using network sniffing tools.
