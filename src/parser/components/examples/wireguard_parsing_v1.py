import pyshark

def is_wireguard_packet(packet):
    """
    Determines if a packet is a WireGuard VPN packet based on the following heuristic:
      a) The packet must be UDP.
      b) The source or destination port must be 51820 (default WireGuard port).
      c) The UDP payload must be at least 4 bytes long.
      d) The first 4 bytes of the payload, interpreted as a little-endian integer,
         should be 1, 2, or 3 corresponding to WireGuard handshake message types:
             1 - Handshake Initiation
             2 - Handshake Response
             3 - Cookie Reply

    Returns:
        bool: True if the packet is likely a WireGuard packet, False otherwise.
    """
    # Check if the packet contains a UDP layer.
    if 'UDP' not in packet:
        return False
    
    udp_layer = packet.udp

    # Check if the UDP packet uses the default WireGuard port (51820)
    if udp_layer.srcport == '51820' or udp_layer.dstport == '51820':
        return False

    # Ensure that the UDP payload exists.
    if not hasattr(udp_layer, 'payload'):
        return False

    # Clean the UDP payload hex string (remove colons and spaces) and convert to bytes.
    payload_hex = udp_layer.payload.replace(":", "").replace(" ", "")
    try:
        payload_bytes = bytes.fromhex(payload_hex)
    except Exception as e:
        # Conversion failed, so not a valid WireGuard packet.
        return False

    # Verify that the payload is long enough to contain the 4-byte message type.
    if len(payload_bytes) < 4:
        return False

    # Interpret the first 4 bytes as a little-endian integer.
    # msg_type = int.from_bytes(payload_bytes[0:4], byteorder='little')
    msg_type = int(payload_bytes[0])
    # Check if the message type matches one of the known WireGuard handshake types.
    if msg_type in {1, 2, 3}:
        # Check if next 3 bytes (bytes 1-3) are all zero
        if payload_bytes[1] != 0 or payload_bytes[2] != 0 or payload_bytes[3] != 0:
            return False
        return True

    return False

def main():
    # Replace with the path to your pcap file.
    pcap_file = '/home/mpaul/projects/mpaul/parsing/packet-parsing/data/wireguard.1.pcap'
    # Use keep_packets=False to handle large files without high memory usage.
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)
    
    total_packets = 0
    wg_packet_count = 0

    for packet in capture:
        total_packets += 1
        try:
            if is_wireguard_packet(packet):
                wg_packet_count += 1
                print(f"Packet #{total_packets} is a WireGuard VPN packet.")
                # Optionally print additional packet information.
                if hasattr(packet, 'ip'):
                    print(f"   Source IP: {packet.ip.src} -> Destination IP: {packet.ip.dst}")
                print("-" * 50)
        except Exception as e:
            print(f"Error processing packet #{total_packets}: {e}")

    print(f"Total packets processed: {total_packets}")
    print(f"Total WireGuard VPN packets detected: {wg_packet_count}")

if __name__ == '__main__':
    main()
