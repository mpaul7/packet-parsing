from typing import Dict, Any
import pandas as pd

from src.parser.components.pyshark_extractor import PySharkExtractor
from src.parser.components.nfstream_extractor import NFStreamExtractor
from src.parser.components.ndpi_extractor import NDPIExtractor
from src.parser.components.flow_mapper import FlowMapper
from src.parser.utils.common import get_reverse_ip
from src.parser.utils.common import ip_swap

class PCAPExtract:
    """Main class for parsing from PCAP packet data"""
    
    def __init__(self):
        self.extractors = {
            'pyshark': PySharkExtractor(),
            'nfstream': NFStreamExtractor(),
            'ndpi': NDPIExtractor()
        }
        self.flow_mapper = FlowMapper()

    
    def extract_data(self, pcap_file: str) -> pd.DataFrame:
        """Extract packet metadata from pcap file using multiple extractors
        
        Args:
            pcap_file: Path to pcap file
            
        Returns:
            pd.DataFrame: Combined features from all extractors
        """
        """ Extract features using different parsers"""
        """ Pyshark also extracts packet information related to different VPN types. 
        For exampl: OpenVPN, Wiregaurd, IPSecVPN, CiscoVPN."""
        
        # print("Extracting features using PyShark")
        # df_pyshark = self.extractors['pyshark'].extract(pcap_file)
        print("Extracting features using NFStream")
        df_nfs = self.extractors['nfstream'].extract(pcap_file)
        df_nfs = ip_swap(df_nfs)
        print("Extracting features using nDPI")
        df_ndpi = self.extractors['ndpi'].extract(pcap_file)
        df_ndpi = ip_swap(df_ndpi)
        """ Get reverse IP information """
        # df = get_reverse_ip(df_pyshark)

        """ Map features from different extractors """
        df = self.flow_mapper.map(df_nfs, df_ndpi, with_timestamp=True)
              
        return df