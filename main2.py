"""Description: 
Date: 2025-01-26
Author: TW

This script is used to parse packet data from pcap files and extract features using different parsers.
The extracted features are then saved in a CSV file.
"""

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

import os
import click
import datetime

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
    start_time = datetime.datetime.now()
    head, tail = os.path.split(pcap)
    extractor = PCAPExtract()
    df = extractor.extract_data(pcap)
    df['file_name'] = tail
    print(df.head())
    df = ip_swap(df)
    print(df.head())
    
    mac_dict = {
        '30:05:5c:71:39:03' : 'brother_printer_1',
        '00:1b:a9:ba:25:c9' : 'brother_printer_2',
        '52:54:00:10:cd:dc' : 'git_server',
        'c8:60:00:ee:7d:7a' : 'pc_Craig',
        '04:92:26:57:0a:64' : 'pc_Jennie',
        '28:df:eb:43:46:44' : 'laptop_Manjinder',
        '00:50:b6:16:59:08' : 'laptop Monica', 
        'c8:60:00:c8:78:91' : 'pc_Shubham',
        '00:1f:54:80:32:c7' : 'lorex_webcam',
        '14:eb:b6:94:32:fb' : 'tapo_TP_Link_camera',
        '4c:ed:fb:a7:96:b5' : 'pc_soundcloud',
        } 
    df['device'] = df.mac.map(mac_dict)
    df.to_csv(os.path.join(output, tail.replace('pcap', 'csv')))
    end_time = datetime.datetime.now()
    print(f"Time taken: {end_time - start_time}")

@cli.command(name='ipswap')
@click.argument('input_csv', type=click.Path(exists=True))
@click.argument('output_csv', type=click.Path(exists=True))
def parse_new(input_csv, output_csv):
    start_time = datetime.datetime.now()
    head, tail = os.path.split(input_csv)
    extractor = PCAPExtract()
    df = extractor.extract_data(pcap)
    df['file_name'] = tail
    
    df = ip_swap(df)
    df.to_csv(os.path.join(output, tail.replace('pcap', 'csv')))
    end_time = datetime.datetime.now()
    print(f"Time taken: {end_time - start_time}")

if __name__ == "__main__":
    cli()
