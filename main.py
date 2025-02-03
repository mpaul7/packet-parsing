import os
import click
import glob
import timeit
import subprocess
import pandas as pd
import numpy as np
import hashlib
import time
from src.parser.utils.common import add_hash_col
from src.parser.components.packet_parsing import PCAPExtract
from ipaddress import IPv4Interface
from ipaddress import IPv4Network
from ipaddress import IPv4Address
from netaddr import IPNetwork
from collections import defaultdict

import warnings
import time

warnings.simplefilter(action='ignore', category=FutureWarning)


@click.group()
def cli():
    """ Label flows based on ports (dns, http), 'reverse_ip' and 'sni' """
    pass



@cli.command(name='parse')
@click.argument('pcap', type=click.Path(exists=True))
@click.argument('output', type=click.Path(exists=True))
def packet_parse(pcap, output):
    try:
        
        print(pcap)
        _head, _tail = os.path.split(pcap)
        """ Extract  SNI, NFS and DNSa data """
        df = PCAPExtract().extract_data(pcap)

        """ nDPI extraction"""
        ndpi_cmd = ['/home/tw/projects/ndpi_bin/nDPI/example/ndpiReader', '-i', pcap, '-q',  '-C', 'output_ndpi.csv']
        subprocess.run(ndpi_cmd)
        df_ndpi_bin = pd.read_csv('output_ndpi.csv')
        df_ndpi_data = pd.read_csv('/home/tw/projects/data_capture/datacap/general_scripts/twpa/ndpi_data/ndpi_label.csv')
        
    except Exception as e:
        """"""
        print(e, 1111)
        pass

if __name__ == "__main__":
    cli()
