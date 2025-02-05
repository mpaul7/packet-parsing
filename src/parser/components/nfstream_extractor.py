from nfstream import NFStreamer
import pandas as pd
from .base_extractor import BaseExtractor

class NFStreamExtractor(BaseExtractor):
    """Extracts packet features using NFStream"""
    
    def extract(self, pcap_file: str) -> pd.DataFrame:
        df = NFStreamer(source=pcap_file).to_pandas()
        df = df[['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
                'bidirectional_first_seen_ms', 'application_name',
                'application_category_name', 'requested_server_name']].copy()
                
        df.rename(columns={
            'src_ip': 'sip',
            'src_port': 'sport', 
            'dst_ip': 'dip',
            'dst_port': 'dport',
            'bidirectional_first_seen_ms': 'first_timestamp_ms',
            'application_name': 'nfs_app_label',
            'application_category_name': 'nfs_traffic_type_label',
            'requested_server_name': 'nfs_requested_server_name'
        }, inplace=True)
        
        return df