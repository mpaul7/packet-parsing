import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

import os
import click

from src.parser.components.data_extraction import PCAPExtract
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
def parse_new(pcap, output):
    head, tail = os.path.split(pcap)
    extractor = PCAPExtract()
    df = extractor.extract_data(pcap)
    df['file_name'] = tail
    
    df = ip_swap(df)
    df.to_csv(os.path.join(output, tail.replace('pcap', 'csv')))

if __name__ == "__main__":
    cli()
