import pyshark

def is_ipsec_vpn_packet(packet):
    """
    Determines if a packet is related to IPSec VPN based on the following heuristic:
      a) Packet must be UDP or TCP.
      b) For UDP: source or destination port must be 4500, 4501, or 500.
         For TCP: destination port must be 4500.
      c) 17th byte (index 16) of the payload must be in the range 1 to 54.
      d) 18th byte (index 17) must be a version number (0x10 for version1 or 0x20 for version2).
      e) 19th byte (index 18) must be an exchange type (range 1 to 5 or 34 to 54).
      f) 29th byte (index 28) must be the next payload field in the generic payload header (range 1 to 54).
    """
    payload_hex = None

    # Check if the packet is UDP.
    if 'UDP' in packet:
        udp_layer = packet.udp
        # Verify that either source or destination port is one of 4500, 4501, or 500.
        if udp_layer.srcport not in ['4500', '4501', '500'] and udp_layer.dstport not in ['4500', '4501', '500']:
            return False
        # Get UDP payload if available.
        if hasattr(udp_layer, 'payload'):
            payload_hex = udp_layer.payload
        else:
            return False

    # Else if the packet is TCP.
    elif 'TCP' in packet:
        tcp_layer = packet.tcp
        # For TCP, the destination port must be 4500.
        if tcp_layer.dstport != '4500':
            return False
        # Get TCP payload if available.
        if hasattr(tcp_layer, 'payload'):
            payload_hex = tcp_layer.payload
        else:
            return False
    else:
        # Not UDP or TCP.
        return False

    # Clean the hex string (remove any colons or spaces) and convert to bytes.
    payload_hex = payload_hex.replace(":", "").replace(" ", "")
    print("payload_hex", payload_hex, "=====")
    try:
        payload_bytes = bytes.fromhex(payload_hex)
    except Exception as e:
        # If conversion fails, skip the packet.
        return False

    # Ensure the payload is long enough to check the required bytes.
    if len(payload_bytes) < 29:
        print("Payload length is less than 29")
        return False

    # (c) Check the 17th byte (index 16): should be in range 1 to 54.
    next_payload_17 = payload_bytes[16]
    if not (1 <= next_payload_17 <= 54):
        print("next_payload_17", next_payload_17, "17th byte is not in range 1 to 54")
        return False

    # (d) Check the 18th byte (index 17): version number must be 0x10 (v1) or 0x20 (v2).
    version_byte = payload_bytes[17]
    if version_byte not in (0x10, 0x20):
        print("version_byte", version_byte, "18th byte is not 0x10 or 0x20")
        return False

    # (e) Check the 19th byte (index 18): exchange type must be in range 1-5 or 34-54.
    exchange_type = payload_bytes[18]
    if not ((1 <= exchange_type <= 5) or (34 <= exchange_type <= 54)):
        print("exchange_type", exchange_type, "19th byte is not in range 1-5 or 34-54")
        return False

    # (f) Check the 29th byte (index 28): next payload field in generic payload header, 
    # here we assume valid if it is in range 1 to 54.
    next_payload_29 = payload_bytes[28]
    if not (1 <= next_payload_29 <= 54):
        print("next_payload_29", next_payload_29, "29th byte is not in range 1 to 54")
        return False

    # All heuristic conditions met: consider this an IPSec VPN packet.
    return True

def main():
    # Replace 'your_capture.pcap' with the path to your pcap file.
    pcap_file = '/home/mpaul/projects/mpaul/parsing/packet-parsing/data/ipsec_client.pcap'
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)
    
    ipsec_count = 0
    total_count = 0

    for packet in capture:
        total_count += 1
        try:
            if is_ipsec_vpn_packet(packet):
                ipsec_count += 1
                print(f"Packet #{total_count}: IPSec VPN packet detected.")
                # Optionally print additional information if available.
                if hasattr(packet, 'ip'):
                    print(f"  Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}")
                if 'UDP' in packet:
                    print(f"  UDP Ports: {packet.udp.srcport} -> {packet.udp.dstport}")
                elif 'TCP' in packet:
                    print(f"  TCP Destination Port: {packet.tcp.dstport}")
                print("-" * 50)
        except Exception as e:
            print(f"Error processing packet #{total_count}: {e}")

    print(f"Processed {total_count} packets, found {ipsec_count} IPSec VPN packets.")

if __name__ == "__main__":
    main()
