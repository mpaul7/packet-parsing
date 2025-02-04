import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

import os
import click
import pandas as pd
import subprocess

from src.parser.components.packet_parsing import PCAPExtract
from src.parser.utils.common import ip_swap

@click.group()
def cli():
    """ Parse packet data in Pcap files"""
    pass

final_col = ['sip', 'sport', 'dip', 'dport', 'protocol', 'nfs_app_label', 'nfs_traffic_type_label',
            'dns_query', 'dns_ans', 'fqdn', 'sni', 'vpn']

@cli.command(name='parse')
@click.argument('pcap', type=click.Path(exists=True))
@click.argument('output', type=click.Path(exists=True))
def packet_parse(pcap, output):
    try:
        
        print(pcap)
        _head, _tail = os.path.split(pcap)
        """ Extract  SNI, NFS and DNSa data """
        df = PCAPExtract().extract_data(pcap)
        df = ip_swap(df)
        # print(df)
        df.to_csv(os.path.join(output, _tail.replace('pcap', 'csv')))
    except Exception as e:
        print(e, 1111)
        pass

if __name__ == "__main__":
    cli()
