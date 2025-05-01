import hashlib
import socket
import numpy as np
import ipaddress
import pandas as pd

def add_hash_col(df: pd.DataFrame)->pd.DataFrame:
    """
    Add a hash column to the dataframe
    """
    df = df.astype({'sport' : int, 'dport' : int, 'protocol': int})
    df  = df.copy()
    def calculate_flow_hash(row):
        m = hashlib.md5()
        hash = ''.join([str(row.sip), str(row.sport), str(row.dip), str(row.dport), str(row.protocol)#, str(row.first_timestamp)
                        ])
        m.update(hash.encode())
        return m.hexdigest()

    def populate_flow_hashes(df):
        hash= [calculate_flow_hash(row) for _, row in df.iterrows()]
        df['hash'] = hash
    populate_flow_hashes(df)
    return df

def ip_swap(df: pd.DataFrame)->pd.DataFrame:
    """
    Swap if the sip is public and the dip is private,
    or if both addresses have the same privacy levels, swap if the sip is well known
    """
    def in_classA_private(ip):
        return ((ip & 0xFF000000) == 0x0A000000)

    def in_classB_private(ip):
        return ((ip & 0xFFF00000) == 0xAC100000)

    def in_classC_private(ip):
        return ((ip & 0xFFFF0000) == 0xC0A80000)

    def in_private(ip):
        return in_classA_private(ip) or in_classB_private(ip) or in_classC_private(ip)

    WELL_KNOWN_PORTS = [1311, 5986, 8243, 8333, 8531, 8888, 9443, 5985, 8000, 8008, 8080, 8243, 8403, 8530, 8887, 9080,
                        16080]

    # method to check if the port is wellknown
    def is_wellknown(port):
        return ((port < 1024) | (port in WELL_KNOWN_PORTS))

    # method to convert ip address to bytes then to int
    def convert_to_int(ip):
        try:
            ip_bin = socket.inet_pton(socket.AF_INET, ip)
            ip_int = int.from_bytes(ip_bin, byteorder='big')
            return ip_int
        except socket.error:
            return False  # Handle invalid IP addresses

    # IP comparison columns
    df['sip_int'] = df.sip.apply(convert_to_int)
    df['dip_int'] = df.dip.apply(convert_to_int)

    # swap if the sip is public and the dip is private
    swap_ind = df.loc[(df['sip_int'].apply(in_private) == False) & (df['dip_int'].apply(in_private) == True)].index
    # or if both addresses have the same privacy levels, swap if the sip is well known
    swap_ind = swap_ind.append(df.loc[(df['sip_int'].apply(in_private) == df['dip_int'].apply(in_private)) & (
                df.sport.apply(is_wellknown) == True)].index)

    # swap the column name for the rows that meet the above criteria
    df_ip_swapped = df.loc[swap_ind].rename(columns={'sip': 'dip', 'sport': 'dport', 'dip': 'sip', 'dport': 'sport'})
    # replace the data needs to be updated with swapped ip
    df.loc[swap_ind] = df_ip_swapped

    df.drop(columns=['sip_int', 'dip_int'], inplace=True)

    return df

def is_openvpn_udp_packet(payload):
    """
    Check if a packet is an OpenVPN packet by examining its opcode.
    
    Args:
        payload (bytes): The packet payload
        
    Returns:
        tuple: (is_openvpn, packet_type, opcode_hex)
    """
    if not payload or len(payload) < 1:
        return False, None, None
    
    payload_str = ''.join(c for c in payload if c.isalnum())
    payload_bytes = bytes.fromhex(payload_str) if isinstance(payload, str) else payload
    
    """Apply mask 0xF8 (11111000) to get first 5 bits"""
    opcode = payload_bytes[0] & 0xF8  
    
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
        print(f"UDP OpenVPN packet type: {hex(opcode)} {packet_type}")
        return True, packet_type, hex(opcode)
    
    return False, None, hex(opcode)

def is_openvpn_tcp_packet(payload):
    """
    Check if a TCP packet is an OpenVPN packet.
    
    Args:
        payload_bytes (bytes): The packet payload
        
    Returns:
        tuple: (is_openvpn, packet_type, opcode_hex)
    """
    try:
        """TCP OpenVPN packets need minimum 3 bytes (2 for length + 1 for opcode)"""
        

        payload_str = ''.join(c for c in payload if c.isalnum())
        payload_bytes = bytes.fromhex(payload_str) if isinstance(payload, str) else payload


        if not payload_bytes or len(payload_bytes) < 3:
            return False, None, None
    
        """Apply mask 0xF8 (11111000) to get first 5 bits"""
        opcode = payload_bytes[0] & 0xF8  
        """Skip the first 2 bytes (packet length) and get the opcode from the third byte"""
        opcode = payload_bytes[2] & 0xF8  # Apply mask 0xF8 (11111000) to get first 5 bits
        
        """Define OpenVPN opcodes"""
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
        
        """Get packet length from first 2 bytes"""
        packet_length = int.from_bytes(payload_bytes[0:2], byteorder='big')
        
        """Check if opcode matches any known OpenVPN opcode"""
        if opcode in OPENVPN_OPCODES:
            packet_type = OPENVPN_OPCODES[opcode]
            return True, packet_type, {
                'opcode': hex(opcode),
                'length': packet_length
            }
        
        return False, None, None
        
    except Exception as e:
        print(f"Error in is_openvpn_tcp_packet: {e}")
        return False, None, None
    
def is_cisco_vpn_packet(payload):
    """
    Check if a packet is a Cisco VPN packet by examining its signature and headers.
    
    Args:
        payload (bytes): The packet payload
        
    Returns:
        tuple: (is_cisco_vpn, packet_type, details)
    """
    try:
        if not payload or len(payload) < 8:  # Minimum length for Cisco header
            return False, None, None
            
        # Cisco DTLS Session ID (0x01) and Version (0x01) markers
        CISCO_DTLS_MARKER = b'\x01\x00\x00\x00\x00\x00\x00\x01'
        # Cisco SSL VPN marker
        CISCO_SSL_MARKER = b'STF\x01'
        
        # Define Cisco packet types
        CISCO_PACKET_TYPES = {
            0x01: "Session Request",
            0x03: "Session Response",
            0x05: "Keep Alive",
            0x07: "SSL Tunnel Data",
            0x09: "DTLS Tunnel Data",
            0x0b: "Logout Request",
            0x0d: "Session Terminate"
        }
        
        # Check for DTLS tunnel
        if payload.startswith(CISCO_DTLS_MARKER):
            if len(payload) >= 12:
                packet_type = payload[8] & 0xFF
                if packet_type in CISCO_PACKET_TYPES:
                    return True, "DTLS", {
                        'type': CISCO_PACKET_TYPES[packet_type],
                        'code': hex(packet_type)
                    }
        
        # Check for SSL tunnel
        elif payload.startswith(CISCO_SSL_MARKER):
            if len(payload) >= 8:
                packet_type = payload[4] & 0xFF
                if packet_type in CISCO_PACKET_TYPES:
                    return True, "SSL", {
                        'type': CISCO_PACKET_TYPES[packet_type],
                        'code': hex(packet_type)
                    }
        
        return False, None, None
        
    except Exception as e:
        print(f"Error in is_cisco_vpn_packet: {e}")
        return False, None, None
    
def is_ipsec_vpn_packet_v1(packet):
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
        return True


    # Check for ESP or AH layers which are used for IPsec data
    if hasattr(packet, 'esp') or hasattr(packet, 'ah'):
        return True

    # Alternatively, check the IP protocol field if available (50 for ESP, 51 for AH)
    if hasattr(packet, 'ip'):
        proto = packet.ip.get_field_value('proto')
        if proto in ['50', '51']:
            return True

    return False

def is_ipsec_vpn_packet_v2(payload):
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

    """Clean the hex string (remove any colons or spaces) and convert to bytes."""
    payload_hex = payload.replace(":", "").replace(" ", "")
    try:
        payload_bytes = bytes.fromhex(payload_hex)
    except Exception as e:
        # If conversion fails, skip the packet.
        return False

    """Ensure the payload is long enough to check the required bytes."""
    if len(payload_bytes) < 29:
        return False

    """Check the 17th byte (index 16): should be in range 1 to 54."""
    payload_17 = payload_bytes[16]
    if not (1 <= payload_17 <= 54):
        return False

    """Check the 18th byte (index 17): version number must be 0x10 (v1) or 0x20 (v2)."""
    version_byte = payload_bytes[17]
    if version_byte not in [16, 32]:  # 0x10 = 16, 0x20 = 32 in decimal
        return False

    """Check the 19th byte (index 18): exchange type must be in range 1-5 or 34-54."""
    exchange_type = payload_bytes[18]
    if not ((1 <= exchange_type <= 5) or (34 <= exchange_type <= 54)):
        return False

    """Check the 29th byte (index 28): next payload field in generic payload header, 
    here we assume valid if it is in range 1 to 54."""
    next_payload_29 = payload_bytes[28]
    if not (1 <= next_payload_29 <= 54):
        return False

    """All heuristic conditions met: consider this an IPSec VPN packet."""
    return True

def is_wireguard_packet(payload):
    """
    Determines if a packet is a WireGuard VPN packet based on the following heuristic:
      a) The packet must be UDP.
      b) The source or destination port must be 51820 (default WireGuard port).
      c) The UDP payload must be at least 32 bytes long.
      d) The first byte of the payload should be 1, 2, 3, 4 corresponding to WireGuard handshake message types:
             1 - Handshake Initiation
             2 - Handshake Response
             3 - Cookie Reply
             4 - Transport Message
      e) The length of the payload should match the expected length based on the message type.
      f) The first 3 bytes of the payload should be zero. These are reserved and always zero.  
    Returns:
        bool: True if the packet is likely a WireGuard packet, False otherwise.
    """
   
    """ Clean the UDP payload hex string (remove colons and spaces) and convert to bytes."""
    payload_hex = payload.replace(":", "").replace(" ", "")
    try:
        payload_bytes = bytes.fromhex(payload_hex)
    except Exception as e:
        # Conversion failed, so not a valid WireGuard packet.
        return False

    """Verify that the payload is long enough to contain the 4-byte message type."""
    if len(payload_bytes) < 32:
        return False

    """Interpret the first 4 bytes as a little-endian integer."""
    # msg_type = int.from_bytes(payload_bytes[0:4], byteorder='little')
    msg_type = int(payload_bytes[0])
    """Check payload length based on message type"""
    expected_lengths = {
        1: 148,  # Handshake Initiation
        2: 92,   # Handshake Response 
        3: 64,   # Cookie Reply
        4: 32    # Transport Message (minimum)
    }

    if msg_type in expected_lengths:
        # For message type 4, which is transport message, check if length is at least 32
        if msg_type == 4:
            if len(payload_bytes) < expected_lengths[msg_type]:
                return False
        # For other types, check exact length match
        elif len(payload_bytes) != expected_lengths[msg_type]:
            return False

        # Check that bytes 1-3 are zero
        if payload_bytes[1] != 0 or payload_bytes[2] != 0 or payload_bytes[3] != 0:
            return False
            
        return True

    return False
    
    
def get_reverse_ip(df: pd.DataFrame)->pd.DataFrame:
    """
    Get the reverse IP address for a given IP address.
    """
    df['reverse_ip'] = np.nan
    for i in range(len(df)):
        dip = str((df.loc[i, 'dip']))
        if not ipaddress.ip_address(dip).is_private:
            try:
                domain_name = socket.gethostbyaddr(dip)[0]
                df.loc[i, 'reverse_ip'] = domain_name
            except Exception as e:
                pass
    return df