import pyshark

def is_ipsec_vpn_packet(packet):
    """
    Check if a packet is related to an IPsec VPN connection.
    
    The function uses several heuristics:
      - Presence of ISAKMP (for IKEv1) or IKEv2 layers.
      - UDP packets with source or destination port 500 or 4500.
      - Presence of ESP or AH layers, or IP protocol numbers 50 (ESP) or 51 (AH).
      
    Args:
        packet (pyshark.packet.packet.Packet): A packet from Pyshark.
        
    Returns:
        bool: True if the packet is likely an IPsec VPN packet, False otherwise.
    """
    # Check for IKE layers (ISAKMP for IKEv1 or ikev2 for IKEv2)
    if hasattr(packet, 'isakmp') or hasattr(packet, 'ikev2'):
        print("ISAKMP or IKEv2 layer found")
        return True

    # Check if packet has a UDP layer and if the ports are commonly used for IPsec/IKE
    if 'UDP' in packet:
        udp_layer = packet.udp
        print(udp_layer.srcport, udp_layer.dstport, "=====")
        if udp_layer.srcport in ['500', '4500'] or udp_layer.dstport in ['500', '4500']:
            print(udp_layer.srcport, udp_layer.dstport, "=====")
            return True

    # Check for ESP or AH layers which are used for IPsec data
    if hasattr(packet, 'esp') or hasattr(packet, 'ah'):
        print("ESP or AH layer found")
        return True

    # Alternatively, check the IP protocol field if available (50 for ESP, 51 for AH)
    if hasattr(packet, 'ip'):
        proto = packet.ip.get_field_value('proto')
        
        if proto in ['50', '51']:
            print(proto, "=====")
            return True

    return False


def main():
    # Replace 'your_capture.pcap' with the path to your pcap file.
    pcap_file = '/home/mpaul/projects/mpaul/parsing/packet-parsing/data/ipsec_client.pcap'
    # Use keep_packets=False to avoid memory issues with large pcap files.
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)
    
    ipsec_packet_count = 0
    total_packets = 0

    for packet in capture:
        total_packets += 1
        try:
            if is_ipsec_vpn_packet(packet):
                ipsec_packet_count += 1
                print("Found an IPsec VPN related packet:")
                # Optionally, print some basic info (IP addresses, layers, etc.)
                if hasattr(packet, 'ip'):
                    print(f"   Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}")
                if hasattr(packet, 'udp'):
                    print(f"   UDP Ports: {packet.udp.srcport} -> {packet.udp.dstport}")
                # Print a summary of the packet layers
                print("   Layers:", [layer.layer_name for layer in packet.layers])
                print("-" * 50)
        except Exception as e:
            print(f"Error processing packet: {e}")

    print(f"Processed {total_packets} packets.")
    print(f"Found {ipsec_packet_count} IPsec VPN related packets.")

if __name__ == "__main__":
    main()
