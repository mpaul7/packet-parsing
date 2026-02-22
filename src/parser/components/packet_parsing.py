import os
import socket
import ntpath
import numpy as np
import pandas as pd
import pyshark
import dpkt
import hashlib
import ipaddress
import subprocess


from nfstream import NFStreamer
from ipaddress import IPv4Network
from ipaddress import IPv4Address
from src.parser.utils.common import (is_openvpn_udp_packet, 
                                    is_openvpn_tcp_packet, 
                                    is_ipsec_vpn_packet_v1, 
                                    is_ipsec_vpn_packet_v2,
                                    is_wireguard_packet)

import nest_asyncio
nest_asyncio.apply()



class PCAPExtract:
    """_summary_
    """
    def get_dns_sni_labels_pyshark(self, pcap):
        pcap = pyshark.FileCapture(pcap)
        flows = {}
        for pkt in pcap:
            sip = sport = dip = dport = protocol = vpn = http_host = dns_query = dns_ans = fqdn = sni = 0
            try:
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
                        type = "TCP"
                        sport = pkt.tcp.srcport
                        dport = pkt.tcp.dstport
                        if "HTTP" in pkt:
                            type = "HTTP"
                            http_host = pkt.http.host
                        if "TLS" in pkt:
                            type = "TLS"
                            record = pkt.tls.record
                            if "Client Hello" in record:
                                sni = pkt.tls.handshake_extensions_server_name
                        """ check for IPSec packets in UDP """
                        if sport in ['4500', '500'] and dport in ['4500', '500']:
                            print(sport, dport)
                            # Get UDP payload if available.
                            if hasattr(pkt.udp, 'payload'):
                                if sport == '500':
                                    payload = pkt.udp.payload
                                    # 
                                elif sport == '4500':
                                    payload = pkt.udp.payload
                                    
                                    """ Ref [RFC 3948] - drop the first 12 bytes of the payload to get the actual IPsec packet 
                                    Non-ESP Marker is 4 bytes of zero aligning with the SPI field of an ESP packet."""
                                    payload = payload[12:]
                                is_ipsec = is_ipsec_vpn_packet_v2(payload)
                                if is_ipsec:
                                    type = "IPSec"
                                    vpn = "IPSecVPN"
                        if int(sport) == 1194 or int(dport) == 1194:  # Standard OpenVPN port
                            type = "OpenVPN"
                            is_openvpn, packet_type, opcode_hex = is_openvpn_tcp_packet(pkt.udp.payload)
                            if is_openvpn:
                                vpn = "OpenVPN"
                    if "UDP" in pkt:
                        sport = pkt.udp.srcport
                        dport = pkt.udp.dstport
                        
                        """ check for IPSec packets in UDP """
                        if sport in ['4500', '500'] and dport in ['4500', '500']:
                            # Get UDP payload if available.
                            if hasattr(pkt.udp, 'payload'):
                                if sport == '500':
                                    payload = pkt.udp.payload
                                elif sport == '4500':
                                    payload = pkt.udp.payload
                                    
                                    """ Ref [RFC 3948] - drop the first 12 bytes of the payload to get the actual IPsec packet 
                                    Non-ESP Marker is 4 bytes of zero aligning with the SPI field of an ESP packet."""
                                    payload = payload[12:]
                                is_ipsec = is_ipsec_vpn_packet_v2(payload)
                                if is_ipsec:
                                    type = "IPSec"
                                    vpn = "IPSecVPN"
                                    
                        """ check for OpenVPN packets in UDP """
                        if int(sport) == 1194 or int(dport) == 1194:  # Standard OpenVPN port
                            type = "OpenVPN"
                            is_openvpn, packet_type, opcode_hex = is_openvpn_udp_packet(pkt.udp.payload)
                            if is_openvpn:
                                vpn = "OpenVPN"
                        """ check for WireGuard packets in UDP """
                        if sport == '51820' or dport == '51820':
                            if hasattr(pkt.udp, 'payload'):
                                type = "WireGuard"
                                is_wireguard = is_wireguard_packet(pkt.udp.payload)
                                if is_wireguard:
                                    
                                    vpn = "WireGuard"
                        if "DNS" in pkt:
                            type = "DNS"
                            if pkt.dns.flags_response.int_value == 0: #pkt.dns.flags == '0x0100':  # dns query
                                dns_query = pkt.dns.qry_name
                                fqdn = socket.getfqdn(dns_query)
                            elif pkt.dns.flags_response.int_value == 1: #pkt.dns.flags == '0x8180':  # dns answer
                                if pkt.dns.qry_type == '1':  # IPv4
                                    dns_ans = pkt.dns.a
                                elif pkt.dns.qry_type == '28':  # IPv6
                                    dns_ans = pkt.dns.aaaa
                        if "QUIC" in pkt:
                            type = "QUIC"
                            if "Client Hello" in pkt.quic.tls_handshake:
                                sni = pkt.quic.tls_handshake_extensions_server_name
                    hash_f = ''.join([str(sip), str(sport), str(dip), str(dport), str(protocol)])
                    hash_b = ''.join([str(dip), str(dport), str(sip), str(sport), str(protocol)])

                    if hash_f in flows:
                        flow = flows[hash_f]
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
                        curr_flow = [sip, sport, dip, dport, protocol, vpn, http_host, dns_query, dns_ans, fqdn, sni]
                        flows[hash_f] = curr_flow
            except Exception as e:
                # print(f'{cnt} - {e}')
                pass
        features = [v for k, v in flows.items()]
        TUPLE_HEADER = ['sip', 'sport', 'dip', 'dport', 'protocol',  'vpn', 'http_host', 'dns_query', 'dns_ans', 'fqdn', 'sni']
        df = pd.DataFrame(features, columns=TUPLE_HEADER)
        return df
    
    def get_nfs_label(self, pcap_file: object) -> object:
        df = NFStreamer(source=pcap_file).to_pandas()
        df = df[
            ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'bidirectional_first_seen_ms',
            'application_name', 'application_category_name', 'requested_server_name']].copy()
        df.rename(
            columns={'src_ip': 'sip', 'src_port': 'sport', 'dst_ip': 'dip', 'dst_port': 'dport',
                    'bidirectional_first_seen_ms': 'first_timestamp_ms',
                    'application_name': 'nfs_app_label',
                    'application_category_name': 'nfs_traffic_type_label',
                    'requested_server_name': 'nfs_requested_server_name'
                    },
            inplace=True)
        return df
    
    def get_ndpi_label(self, pcap_file):
        
        col = ['#flow_id', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
               'ndpi_proto', 'proto_by_ip', 'server_name_sni']
        ndpi = f'{NDPI_HOME}/nDPI/example/ndpiReader'
        ndpi_cmd = [ndpi, '-i', pcap_file, '-q',  '-F', '-q', '-C', 'output_ndpi.csv']
        subprocess.run(ndpi_cmd)
        df_ndpi= pd.read_csv('output_ndpi.csv', usecols=col)
        new_col_names = {'#flow_id': 'flow_id', 'src_ip': 'sip', 'src_port': 'sport', 'dst_ip': 'dip', 'dst_port': 'dport'}
        df_ndpi = df_ndpi.rename(columns=new_col_names)
        df_ndpi['flow_id'] = df_ndpi['flow_id'].replace(np.nan, '0')
        drop_mask = df_ndpi['flow_id'] == '0'
        df_ndpi = df_ndpi.drop(df_ndpi[drop_mask].index)
        return df_ndpi
    
        
    def get_statifc_ip_label(self, df):
        """ Lable the destination ip in the input dataframe based on ndpi_database"""
        df['static_ip'] = 0
        ips = set(df.dip.to_list() + df.sip.to_list())
        df_ndpi_data = pd.read_csv(NDPI_DATA)
        for ip in ips:
            for j in range(len(df_ndpi_data)):
                net_address = str(df_ndpi_data.at[j, 'net_address']).strip(" ")
                if IPv4Address(ip) in IPv4Network(net_address):
                    list_ips2 = [str(ip) for ip in IPv4Network(net_address)]
                    if ip in list_ips2: #IPv4Address(ip) in IPv4Network(net_address):
                        ndpi_label = str(df_ndpi_data.at[j, 'label']).strip(" ")
                        df.loc[df["dip"] == ip, "static_ip"] = ndpi_label
                        df.loc[df["sip"] == ip, "static_ip"] = ndpi_label
                    if IPv4Address(ip) in list_ips2:
                        ndpi_label = str(df_ndpi_data.at[j, 'label']).strip(" ")
                        df.loc[df["dip"] == ip, "static_ip"] = ndpi_label
                        df.loc[df["sip"] == ip, "static_ip"] = ndpi_label
        return df

    def get_reverse_ip(self, df):
        df['reverse_ip'] = np.nan
        for i in range(len(df)):
            dip = str((df.loc[i, 'dip']))
            if not ipaddress.ip_address(dip).is_private:
                try:
                    domain_name = socket.gethostbyaddr(dip)[0]
                    df.loc[i, 'reverse_ip'] = domain_name
                except Exception as e:
                    # print(e, dip,  222)
                    pass
        return df
    
    def _map(self, df_fea, df_label, with_timestamp=True):
        def add_hash_col(df):
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
        df_fea = add_hash_col(df_fea)
        df_label = add_hash_col(df_label)

        keys = ["sip", "sport", "dip", "dport", "protocol", "first_timestamp_ms"]
        if not with_timestamp:
            keys = keys[:-1]
        else:
            df_fea['first_timestamp_ms'] = df_fea['first_timestamp'] // 1000  # convert first timestamp to ms

        df_fea['id'] = df_fea[keys].apply(lambda row: '_'.join(row.values.astype(str)), axis=1)
        df_label['id'] = df_label[keys].apply(lambda row: '_'.join(row.values.astype(str)), axis=1)
        df = df_fea.merge(df_label, how='left', on='hash', suffixes=('', '_y'))
        df = df.drop([col for col in df.columns if col.endswith('_y')], axis=1)  # drop nfs key columns
        df = df.drop(columns=['id'])  # drop id calculation columns
        return df

    def _get_dns_ans(self, dns):
        ans_data = 0
        dns_types = []
        dict_dns_types = {}
        # for qname in dns.qd: 
            # print(qname.name)
        for rr in dns.an:
            if rr.type == dpkt.dns.DNS_A:
                ans_type = 'A'
                
                try:
                    ans_data = socket.inet_ntoa(rr.rdata)
                    if ans_type !=0:
                        dns_types.append(ans_data)
                        dict_dns_types[ans_type] = ans_data
                    else:
                        dns_types.append(0)
                        dict_dns_types[ans_type] = ans_data
                    # print(ans_type, ans_data)
                    # return ans_data
                except (socket.error, ValueError):
                    continue
            elif rr.type == dpkt.dns.DNS_AAAA:
                ans_type = "AAAAA"
                try:
                    ans_data = socket.inet_ntop(socket.AF_INET6, rr.rdata)
                    if ans_type !=0:
                        dns_types.append(ans_data)
                        dict_dns_types[ans_type] = ans_data
                    else:
                        dns_types.append(0)
                        dict_dns_types[ans_type] = ans_data
                except (socket.error, ValueError):
                    continue
            elif rr.type == dpkt.dns.DNS_CNAME:
                ans_type = "CNAME"
                ans_data = rr.cname
                if ans_type !=0:
                    dns_types.append(ans_data)
                    dict_dns_types[ans_type] = ans_data
                else:
                    dns_types.append(0)
                    dict_dns_types[ans_type] = ans_data
            elif rr.type == dpkt.dns.DNS_MX:
                ans_type = "MX"
                ans_data = rr.mxname
                if ans_type !=0:
                    dns_types.append(ans_data)
                    dict_dns_types[ans_type] = ans_data
                else:
                    dns_types.append(0)
                    dict_dns_types[ans_type] = ans_data
                # print(ans_type, ans_data)
                # return ans_data
            elif rr.type == dpkt.dns.DNS_PTR:
                ans_type = "PTR"
                ans_data = rr.ptrname
                if ans_type !=0:
                    dns_types.append(ans_data)
                    dict_dns_types[ans_type] = ans_data
                else:
                    dns_types.append(0)
                    dict_dns_types[ans_type] = ans_data
                # print(ans_type, ans_data)
                # return ans_data
            elif rr.type == dpkt.dns.DNS_NS:
                ans_type = "NS"
                ans_data = rr.nsname
                if ans_type !=0:
                    dns_types.append(ans_data)
                    dict_dns_types[ans_type] = ans_data
                else:
                    dns_types.append(0)
                    dict_dns_types[ans_type] = ans_data
            elif rr.type == dpkt.dns.DNS_SOA:
                ans_type = "SOA"
                ans_data = ",".join([rr.mname,
                                    rr.rname,
                                    str(rr.serial),
                                    str(rr.refresh),
                                    str(rr.retry),
                                    str(rr.expire),
                                    str(rr.minimum)])
                if ans_type !=0:
                    dns_types.append(ans_data)
                    dict_dns_types[ans_type] = ans_data
                else:
                    dns_types.append(0)
                    dict_dns_types[ans_type] = ans_data
            elif rr.type == dpkt.dns.DNS_HINFO:
                ans_type = "HINFO"
                ans_data = " ".join(rr.text)
                if ans_type !=0:
                    dns_types.append(ans_data)
                    dict_dns_types[ans_type] = ans_data
                else:
                    dns_types.append(0)
                    dict_dns_types[ans_type] = ans_data
            elif rr.type == dpkt.dns.DNS_TXT:
                ans_type = "TXT"
                ans_data = str(rr.text)
                if ans_type !=0:
                    dns_types.append(ans_data)
                    dict_dns_types[ans_type] = ans_data
                else:
                    dns_types.append(0)
                    dict_dns_types[ans_type] = ans_data
            elif rr.type == dpkt.dns.DNS_SRV:
                ans_type = "SRV"
                ans_data = rr.srvname
                if ans_type !=0:
                    dns_types.append(ans_data)
                    dict_dns_types[ans_type] = ans_data
                else:
                    dns_types.append(0)
                    dict_dns_types[ans_type] = ans_data
        return ans_data, dns_types, dict_dns_types
    
    def get_dns_sni_labels_dpkt(self, pcap_file):

        flows = {}
        pcap_handle = open(pcap_file, 'rb')
        pcap = dpkt.pcap.Reader(pcap_handle)
        cnt = 1
        for ts, buf in pcap:

            syn_ack = 0
            rst = 0
            sni = '0'
            dns_query = 0
            dns_ans = 0
            FQDN = 0
            dns_types = 0
            handshake = 0
            tls_rec_hs, tls_rec_ccs, tls_rec_app_data, tls_rec_alert, fin_ack = [0] * 5
            filter = 0

            try:
                # Dynamic switch between Mobile and Ethernet
                if pcap.datalink() == dpkt.pcap.DLT_EN10MB:
                    eth = dpkt.ethernet.Ethernet(buf)
                elif pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
                    eth = dpkt.sll.SLL(buf)
                elif pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL2:
                    eth = dpkt.sll2.SLL2(buf)

                """
                Check if Ethernet frame contains IP packet
                """
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data
                sip = socket.inet_ntoa(ip.src)
                dip = socket.inet_ntoa(ip.dst)
                """
                Check the protocol type in the packet, and if it is tcp or udp then use the ports
                This will by-pass flows like ICMP, etc.
                """
                if ip.p not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                    continue
                tcp = ip.data
                sport = int(tcp.sport)
                dport = int(tcp.dport)
                protocol = int(ip.p)
                hash_f = ''.join([str(ip.src), str(sport), str(ip.dst), str(dport), str(protocol)])
                hash_b = ''.join([str(ip.dst), str(dport), str(ip.src), str(sport), str(protocol)])
                # _curr_flow = [sip, sport, dip, dport, protocol, syn_ack, rst, len(tcp.data)]

                if tcp.sport == 53 or tcp.dport == 53:
                    if eth.type == 2048 and ip.p == 17:
                        dns = dpkt.dns.DNS(tcp.data)
                        dns_query = dns.qd[0].name
                        dns_ans, _dns_types, dict_dns_types= self._get_dns_ans(dns)
                        # print(_dns_types)
                        dns_types = _dns_types
                        # print([sip, sport, dip, dport, protocol], dict_dns_types)
                        # FQDN = socket.getfqdn(dns_query)

                # sport = int(tcp.sport)
                # dport = int(tcp.dport)
                # protocol = int(ip.p)
                # hash_f = ''.join([str(ip.src), str(sport), str(ip.dst), str(dport), str(protocol)])
                # hash_b = ''.join([str(ip.dst), str(dport), str(ip.src), str(sport), str(protocol)])
                # _curr_flow = [sip, sport, dip, dport, protocol, syn_ack, rst, len(tcp.data)]

                """
                Parse TLS data
                """

                if len(tcp.data) > 0:
                    if tcp.sport == 443 or tcp.dport == 443:
                        if ip.p == 6:
                            handshake = tcp.data[0]
                            try:
                                tls = dpkt.ssl.TLS(tcp.data)
                                if len(tls.records) >= 1:
                                    handshake = dpkt.ssl.TLSHandshake(tls.records[0].data)
                                    client_hello = handshake.data

                                    for ext in client_hello.extensions:
                                        # try:
                                        if TLS_EXTENSION_TYPES.get(ext[0]) == 'server_name':
                                            sni = str(ext[1], 'utf-8')[5:]
                            except Exception as e:
                                pass

                        elif ip.p == 17:  # TODO: handle client hello of QUIC flows(UDP, using 443 as ports)
                            pass

                if ip.p == 6:
                    if (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK):
                        syn_ack = 1
                    if (tcp.flags & dpkt.tcp.TH_FIN) and (tcp.flags & dpkt.tcp.TH_ACK):
                        fin_ack = 1
                    if tcp.flags & dpkt.tcp.TH_RST:
                        rst = 1

                if hash_f in flows:
                    flow = flows[hash_f]
                    if flow[-10] == '0':
                        # print(type(sni), sni, 111)
                        flow[-10] = sni
                    if syn_ack == 1 and flow[-7] == 0:
                        flow[-7] = 1
                    if handshake == 22:
                        flow[-6] = handshake
                    if handshake == 20:
                        flow[-5] = handshake
                    if handshake == 23:
                        flow[-4] = handshake
                    if handshake == 21:
                        flow[-3] = handshake
                    if fin_ack == 1 and flow[-2] == 0:
                        flow[-2] = 1
                    if rst == 1 and flow[-1] == 0:
                        flow[-1] = 1
                    flows[hash_f] = flow
                elif hash_b in flows:
                    flow = flows[hash_b]
                    if dns_ans != 0 and flow[-8] == 0:
                        flow[-8] = dns_ans
                    if syn_ack == 1 and flow[-7] == 0:
                        flow[-7] = 1
                    if handshake == 22:
                        flow[-6] = handshake
                    if handshake == 20:
                        flow[-5] = handshake
                    if handshake == 23:
                        flow[-4] = handshake
                    if handshake == 21:
                        flow[-3] = handshake
                    if fin_ack == 1 and flow[-2] == 0:
                        flow[-2] = 1
                    if rst == 1 and flow[-1] == 0:
                        flow[-1] = 1
                    flows[hash_b] = flow
                else:
                    filter = f'ip.addr=={dip} && tcp.port=={sport}'
                    curr_flow = [sip, sport, dip, dport, filter, protocol, FQDN, dns_types,
                                sni,
                                dns_query, dns_ans,
                                syn_ack, tls_rec_hs, tls_rec_ccs, tls_rec_app_data, tls_rec_alert, fin_ack, rst]
                    flows[hash_f] = curr_flow
            except Exception as e:
                print(f'{e}')
                pass
            cnt += 1

        features = [v for k, v in flows.items()]
        df = pd.DataFrame(features)
        return df

    def _get_dns_label(self, df=None):
        dns_ans_dict = {}
        for i in range(len(df)):
            try:
                dns_query = str((df.loc[i, 'dns_query']))
                dns_ans = str((df.loc[i, 'dns_ans']))
                dip = str((df.loc[i, 'dip']))

                if (dns_query != '0') & (dns_query != 'nan'):
                    dns_ans_dict[dns_ans] = dns_query
                    dns_ans_dict[dip] = 'dns'

            except Exception as e:
                print(e)

        return dns_ans_dict

    def extract_data(self, file_name):
        def _get_name(path):
            head, tail = ntpath.split(path)
            return tail or ntpath.basename(head)
        
        """Get various dataframes, static_ip and reverse_ip"""
        df_pyshark = self.get_dns_sni_labels_pyshark(file_name)
        # df_pyshark = self.get_dns_sni_labels_dpkt(file_name)
        
        df_nfs = self.get_nfs_label(file_name)
        # df_ndpi = self.get_ndpi_label(file_name)
        # df_static_ip = self.get_statifc_ip_label(df_pyshark)
        df = self.get_reverse_ip(df_pyshark)
        
        """ Map all datagrames based on hash """
        df = self._map(df_nfs, df, with_timestamp=False)
        # df = self._map(df_ndpi, df, with_timestamp=False)
        # df = self._map(df_twc, df, with_timestamp=False)
        df['file_name'] = _get_name(file_name)  # append file name with the features when return the dataframe
        
        return df


