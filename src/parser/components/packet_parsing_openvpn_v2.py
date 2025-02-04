def is_openvpn_packet(payload):
    """
    Check if a packet is an OpenVPN packet by examining its opcode.
    
    Args:
        payload (bytes): The packet payload
        
    Returns:
        tuple: (is_openvpn, packet_type, opcode_hex)
    """
    if not payload or len(payload) < 1:
        return False, None, None
        
    # Extract the first byte and get the opcode (first 5 bits)
    payload_bytes = bytes.fromhex(payload)
    opcode = payload_bytes[0] & 0xF8  # Apply mask 0xF8 (11111000) to get first 5 bits
    
    # Define OpenVPN opcodes
    OPENVPN_OPCODES = {
        0x08: "P_CONTROL_HARD_RESET_CLIENT_V1",
        0x10: "P_CONTROL_HARD_RESET_SERVER_V1",
        0x18: "P_CONTROL_SOFT_RESET_V1",
        0x20: "P_CONTROL_V1",
        0x28: "P_ACK_V1",
        0x30: "P_DATA_V1",
        0x38: "P_CONTROL_HARD_RESET_CLIENT_V2",
        0x40: "P_CONTROL_SOFT_RESET_SERVER_V2",
        0x48: "P_DATA_V2"
    }
    
    # Check if opcode matches any known OpenVPN opcode
    if opcode in OPENVPN_OPCODES:
        packet_type = OPENVPN_OPCODES[opcode]
        return True, packet_type, hex(opcode)
    
    return False, None, hex(opcode)

# Example usage:
def process_packet(pkt):
    """
    Process a packet to determine if it's OpenVPN
    
    Args:
        pkt: Packet object (assuming it has UDP payload)
    """
    try:
        if hasattr(pkt, 'udp') and hasattr(pkt.udp, 'payload'):
            # For UDP packets
            payload = bytes(pkt.udp.payload)
            is_vpn, pkt_type, opcode = is_openvpn_packet(payload)
            
            if is_vpn:
                print(f"OpenVPN packet detected!")
                print(f"Packet type: {pkt_type}")
                print(f"Opcode: {opcode}")
                return True
                
        elif hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload'):
            # For TCP packets (skip first 2 bytes of length)
            payload = bytes(pkt.tcp.payload)[2:]
            is_vpn, pkt_type, opcode = is_openvpn_packet(payload)
            
            if is_vpn:
                print(f"OpenVPN packet detected!")
                print(f"Packet type: {pkt_type}")
                print(f"Opcode: {opcode}")
                return True
                
        return False
        
    except Exception as e:
        print(f"Error processing packet: {e}")
        return False