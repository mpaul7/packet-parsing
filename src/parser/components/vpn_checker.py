
from src.parser.utils.common import (is_openvpn_udp_packet, 
                                    is_openvpn_tcp_packet, 
                                    is_ipsec_vpn_packet_v1, 
                                    is_ipsec_vpn_packet_v2,
                                    is_wireguard_packet)

import nest_asyncio
nest_asyncio.apply()

class VPNPacketChecker:
    """Class to handle VPN packet detection and classification"""
    
    @staticmethod
    def check_ipsec(pkt, sport, dport):
        """Check if packet is IPSec VPN"""
        if sport in ['4500', '500'] and dport in ['4500', '500']:
            if hasattr(pkt.udp, 'payload'):
                payload = pkt.udp.payload
                if sport == '4500':
                    # Ref [RFC 3948] - drop first 12 bytes to get actual IPsec packet
                    # Non-ESP Marker is 4 bytes of zero aligning with SPI field of ESP packet
                    payload = payload[12:]
                    
                is_ipsec = is_ipsec_vpn_packet_v2(payload)
                if is_ipsec:
                    return "IPSecVPN"
        return None

    @staticmethod
    def check_openvpn(pkt, sport, dport):
        """Check if packet is OpenVPN"""
        if int(sport) == 1194 or int(dport) == 1194:  # Standard OpenVPN port
            if hasattr(pkt.udp, 'payload'):
                is_openvpn, _, _ = is_openvpn_udp_packet(pkt.udp.payload)
                if is_openvpn:
                    return "OpenVPN"
        return None

    @staticmethod 
    def check_wireguard(pkt, sport, dport):
        """Check if packet is WireGuard"""
        if sport == '51820' or dport == '51820':
            if hasattr(pkt.udp, 'payload'):
                if is_wireguard_packet(pkt.udp.payload):
                    return "WireGuardVPN"
        return None

    def check_packet(self, pkt, sport, dport):
        """Check packet for any VPN protocol"""
        # Check each VPN type
        vpn_type = self.check_ipsec(pkt, sport, dport)
        if vpn_type:
            return vpn_type, "IPSec"
            
        vpn_type = self.check_openvpn(pkt, sport, dport) 
        if vpn_type:
            return vpn_type, "OpenVPN"
            
        vpn_type = self.check_wireguard(pkt, sport, dport)
        if vpn_type:
            return vpn_type, "WireGuard"
            
        return None, None