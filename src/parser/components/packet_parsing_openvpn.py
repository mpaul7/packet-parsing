import pyshark

def parse_openvpn_packet(payload_hex):
    """
    Given a hex string representing the UDP payload,
    parse the first byte to determine if it's a control or data packet,
    and extract the opcode.
    """
    # Remove any colons if present (Pyshark may return colon-separated hex)
    print(f"payload_hex: {payload_hex}")
    hex_payload = payload_hex.replace(":", "")
    print(f"hex_payload: {hex_payload}")
    
    try:
        payload_bytes = bytes.fromhex(hex_payload)
        print(f"payload_bytes: {payload_bytes}")
    except ValueError as e:
        print(f"Error converting hex to bytes: {e}")
        return None

    if len(payload_bytes) < 1:
        return None

    # Read the first byte
    first_byte = payload_bytes[0]
    print(f"first_byte: {first_byte}")
    # Determine packet type based on the MSB (0x80)
    if first_byte & 0x80:
        # Control packet: the lower 7 bits represent the opcode.
        opcode = first_byte & 0x7F
        print(f"opcode: {opcode} ===============")
        packet_type = "Control"
    else:
        # Data packet: the full byte is the opcode.
        opcode = first_byte
        print(f"opcode: {opcode} ===============")
        packet_type = "Data"

    return packet_type, opcode

def main():
    # Mapping dictionaries for known OpenVPN opcodes.
    control_mapping = {
        0x01: "P_CONTROL_HARD_RESET_CLIENT_V1",
        0x02: "P_CONTROL_HARD_RESET_SERVER_V1",
        0x03: "P_CONTROL_SOFT_RESET_V1",
        0x04: "P_CONTROL_V1",
        0x05: "P_ACK_V1",
        0x07: "P_CONTROL_HARD_RESET_CLIENT_V2",
        0x08: "P_CONTROL_SOFT_RESET_SERVER_V2",
    }
    data_mapping = {
        0x06: "P_DATA_V1",
        0x09: "P_DATA_V2"
    }

    # Replace 'your_capture.pcap' with the path to your pcap file.
    capture = pyshark.FileCapture('/home/mpaul/projects/mpaul/parsing/packet-parsing/data/openvpn_gitClone_vpnEstablished_29-11-2024.pcap')

    for packet in capture:
        # Process only UDP packets that have a payload.
        if 'UDP' in packet and hasattr(packet.udp, 'payload'):
            payload_hex = packet.udp.payload
            result = parse_openvpn_packet(payload_hex)
            if result is None:
                continue

            packet_type, opcode = result

            if packet_type == "Control":
                description = control_mapping.get(opcode, f"Unknown control opcode: 0x{opcode:02x}")
            else:  # Data packet
                description = data_mapping.get(opcode, f"Unknown data opcode: 0x{opcode:02x}")

            print(f"Packet Type: {packet_type} | Opcode: 0x{opcode:02x} | Meaning: {description}")

if __name__ == "__main__":
    main()
