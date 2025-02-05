from abc import ABC, abstractmethod
import pandas as pd

class BaseExtractor(ABC):
    """Base class for all packet extractors"""
    
    @abstractmethod
    def extract(self, pcap_file: str) -> pd.DataFrame:
        """Extract features from pcap file
        
        Args:
            pcap_file: Path to pcap file
            
        Returns:
            pd.DataFrame: Extracted features
        """
        pass