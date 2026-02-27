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
from src.parser.utils.common import ip_swap, mac_dict

@click.group()
def cli():
    """ Parse packet data in Pcap files"""
    pass

@cli.command(name='parse')
@click.argument('pcap', type=click.Path(exists=True))
@click.argument('output', type=click.Path(exists=True))
def parse_new(pcap, output):
    import shutil

    start_time = datetime.datetime.now()
    extractor = PCAPExtract()

    if os.path.isdir(pcap):
        # Make sure output directory exists
        if not os.path.exists(output):
            os.makedirs(output)
        import glob
        files = [os.path.basename(f) for f in glob.glob(os.path.join(pcap, '*.pcap')) if os.path.isfile(f)]
        if not files:
            print(f"No files found in directory: {pcap}")
            return
        for filename in files:
            filepath = os.path.join(pcap, filename)
            if not filename.lower().endswith('.pcap'):
                continue  # Skip non-PCAP files
            print(f"Processing: {filepath}")
            try:
                df = extractor.extract_data(filepath)
                df['file_name'] = filename
                df = ip_swap(df)
                df['device'] = df.mac.map(mac_dict)
                df.rename(columns={'protocol': 'proto'}, inplace=True)
                out_csv_path = os.path.join(output, filename.replace('.pcap', '.csv'))
                df.to_csv(out_csv_path, index=False)
            except Exception as e:
                print(f"Failed to process {filepath}: {e}")
    else:
        head, tail = os.path.split(pcap)
        df = extractor.extract_data(pcap)
        df['file_name'] = tail
        df = ip_swap(df)
        df['device'] = df.mac.map(mac_dict)
        df.rename(columns={'protocol': 'proto'}, inplace=True)
        df.to_csv(os.path.join(output, tail.replace('pcap', 'csv')), index=False)
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
