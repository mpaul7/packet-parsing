import pyshark
import pandas as pd
import socket
from .base_extractor import BaseExtractor
from ..utils.common import is_ipsec_vpn_packet_v2, is_openvpn_tcp_packet, is_openvpn_udp_packet, is_wireguard_packet

class PySharkExtractor(BaseExtractor):
    """Extracts packet features using PyShark"""
    
    def extract(self, pcap_file: str) -> pd.DataFrame:
        pcap = pyshark.FileCapture(pcap_file)
        flows = {}
        pkt1 = pkt2 = pkt3 = 0
        for pkt in pcap:
            sip = sport = dip = dport = protocol = vpn = http_host = dns_query = dns_ans = fqdn = sni = ja3 = ja4 = 0
            mac = 0
            try:
                # print(pkt.field_names)
                # if "eth" in pkt:
                #     mac_src = pkt.eth.src
                #     print(f"MAC Source: {mac_src}")
                mac = pkt.eth.src
                if "ip" not in pkt:
                    continue
                if "IP" in pkt:
                    sip = pkt.ip.src_host
                    dip = pkt.ip.dst_host
                    protocol = pkt.ip.proto
                    if protocol not in ['6', '17']:
                        continue
                    if "ICMP" in pkt:
                        print(pkt.icmp.field_names)
                    if "TCP" in pkt:
                        sport = pkt.tcp.srcport
                        dport = pkt.tcp.dstport
                    elif "UDP" in pkt:
                        sport = pkt.udp.srcport
                        dport = pkt.udp.dstport
                    hash_f = ''.join([str(sip), str(sport), str(dip), str(dport), str(protocol)])
                    hash_b = ''.join([str(dip), str(dport), str(sip), str(sport), str(protocol)])

                    if hash_f not in flows:
                        pkt1 = pkt2 = pkt3 = 0
                        curr_flow = [sip, sport, dip, dport, protocol, mac, ja4, ja3, vpn, http_host, dns_query, dns_ans, fqdn, sni]
                        flows[hash_f] = curr_flow
                        
                    if "TCP" in pkt:
                        print(f"TCP packet")
                        type = "TCP"
                        sport = pkt.tcp.srcport
                        dport = pkt.tcp.dstport
                        # if "HTTP" in pkt:
                        #     type = "HTTP"
                        #     http_host = pkt.http.host
                        if "TLS" in pkt:
                            type = "TLS"
                            record = pkt.tls.record
                            if "Client Hello" in record:
                                sni = pkt.tls.handshake_extensions_server_name
                                ja3 = pkt.tls.handshake_ja3
                                ja4 = pkt.tls.handshake_ja4
                                # print(ja3, ja4)
                        """ check for IPSec packets in UDP """
                        # if sport in ['4500', '500'] and dport in ['4500', '500']:
                        #     print(sport, dport)
                        #     # Get UDP payload if available.
                        #     if hasattr(pkt.udp, 'payload'):
                        #         if sport == '500':
                        #             payload = pkt.udp.payload
                        #             # 
                        #         elif sport == '4500':
                        #             payload = pkt.udp.payload
                                    
                        #             """ Ref [RFC 3948] - drop the first 12 bytes of the payload to get the actual IPsec packet 
                        #             Non-ESP Marker is 4 bytes of zero aligning with the SPI field of an ESP packet."""
                        #             payload = payload[12:]
                        #         is_ipsec = is_ipsec_vpn_packet_v2(payload)
                        #         if is_ipsec:
                        #             type = "IPSec"
                        #             vpn = "IPSecVPN"
                        # if int(sport) == 1194 or int(dport) == 1194:  # Standard OpenVPN port
                        #     type = "OpenVPN"
                        #     is_openvpn, packet_type, opcode_hex = is_openvpn_tcp_packet(pkt.udp.payload)
                        #     if is_openvpn:
                        #         vpn = "OpenVPN"
                    if "UDP" in pkt:
                        sport = pkt.udp.srcport
                        dport = pkt.udp.dstport
                        """ check for IPSec packets in UDP """
                        # if sport in ['4500', '500'] and dport in ['4500', '500']:
                        #     # Get UDP payload if available.
                        #     if hasattr(pkt.udp, 'payload'):
                        #         if sport == '500':
                        #             payload = pkt.udp.payload
                        #         elif sport == '4500':
                        #             payload = pkt.udp.payload
                                    
                        #             """ Ref [RFC 3948] - drop the first 12 bytes of the payload to get the actual IPsec packet 
                        #             Non-ESP Marker is 4 bytes of zero aligning with the SPI field of an ESP packet."""
                        #             payload = payload[12:]
                                # is_ipsec = is_ipsec_vpn_packet_v2(payload)
                                # if is_ipsec:
                                #     type = "IPSec"
                                #     vpn = "IPSecVPN"
                                    
                        """ check for OpenVPN packets in UDP """
                        # if int(sport) == 1194 or int(dport) == 1194:  # Standard OpenVPN port
                        #     type = "OpenVPN"
                        #     is_openvpn, packet_type, opcode_hex = is_openvpn_udp_packet(pkt.udp.payload)
                        #     if is_openvpn:
                        #         vpn = "OpenVPN"
                        """ check for WireGuard packets in UDP """
                        # if sport == '51820' or dport == '51820':
                        #     if hasattr(pkt.udp, 'payload'):
                        #         type = "WireGuard"
                        #         is_wireguard = is_wireguard_packet(pkt.udp.payload)
                        #         if is_wireguard:
                                    
                        #             vpn = "WireGuard"
                        # if "DNS" in pkt:
                        #     type = "DNS"
                        #     if pkt.dns.flags_response.int_value == 0: #pkt.dns.flags == '0x0100':  # dns query
                        #         dns_query = pkt.dns.qry_name
                        #         fqdn = socket.getfqdn(dns_query)
                        #     elif pkt.dns.flags_response.int_value == 1: #pkt.dns.flags == '0x8180':  # dns answer
                        #         if pkt.dns.qry_type == '1':  # IPv4
                        #             dns_ans = pkt.dns.a
                        #         elif pkt.dns.qry_type == '28':  # IPv6
                        #             dns_ans = pkt.dns.aaaa
                        if "QUIC" in pkt:
                            type = "QUIC"
                            if "Client Hello" in pkt.quic.tls_handshake:
                                sni = pkt.quic.tls_handshake_extensions_server_name
                                ja3 = pkt.quic.tls_handshake_ja3
                                ja4 = pkt.quic.tls_handshake_ja4
                                # print(f"QUIC: {ja3}, {ja4}")

                    if hash_f in flows:
                        flow = flows[hash_f]
                        if flow[-9] == 0:
                            flow[-9] = mac
                        if flow[-7] == 0:
                            flow[-7] = ja3
                        if flow[-8] == 0:
                            flow[-8] = ja4
                        if flow[-6] == 0:
                            flow[-6] = vpn
                        if flow[-5] == 0:
                            flow[-5] = http_host
                        if flow[-4] == 0:
                            flow[-4] = dns_query
                        if flow[-3] == 0:
                            flow[-3] = dns_ans
                        if flow[-2] == 0:
                            flow[-2] = fqdn
                        if flow[-1] == 0:
                            flow[-1] = sni
                        flows[hash_f] = flow
                    elif hash_b in flows:
                        flow = flows[hash_b]
                        if flow[-9] == 0:
                            flow[-9] = mac
                        if flow[-7] == 0:
                            flow[-7] = ja3
                        if flow[-8] == 0:
                            flow[-8] = ja4
                        if flow[-6] == 0:
                            flow[-6] = vpn
                        if flow[-5] == 0:
                            flow[-5] = http_host
                        if flow[-4] == 0:
                            flow[-4] = dns_query
                        if flow[-3] == 0:
                            flow[-3] = dns_ans
                        if flow[-2] == 0:
                            flow[-2] = fqdn
                        if flow[-1] == 0:
                            flow[-1] = sni
                        flows[hash_b] = flow
                    else:
                        curr_flow = [sip, sport, dip, dport, protocol, mac, ja4, ja3, vpn, http_host, dns_query, dns_ans, fqdn, sni]
                        flows[hash_f] = curr_flow
            except Exception as e:
                print(f'{pkt.number} - {e}') 
                pass
        features = [v for k, v in flows.items()]
        TUPLE_HEADER = ['sip', 'sport', 'dip', 'dport', 'protocol', 'mac', 'ja4', 'ja3','vpn', 'http_host', 'dns_query', 'dns_ans', 'fqdn', 'sni']
        df = pd.DataFrame(features, columns=TUPLE_HEADER)
        print(df.head())
        return df
