"""Description: 

Date: 2025-02-25
Author: TW

This script is used to extract features from Tranalyser.

"""

import subprocess
import pandas as pd
from pathlib import Path
import click
import os


data_path = [
    '/media/solana/Backup Plus/Data/dvc_data/2020a_Wireline_Ethernet/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/2020c_Mobile_Wifi/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/2021a_Wireline_Ethernet/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/2021c_Mobile_LTE/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/2022a_Wireline_Ethernet/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/2023a_Wireline_Ethernet/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/2023c_Mobile_LTE/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/2023e_MacOS_Wifi/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/2024ag_Wireline_Ethernet/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/2024a_Wireline_Ethernet/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/2024cg_Mobile_LTE/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/2024c_Mobile_LTE/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/2024e_MacOS_Wifi/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Homeoffice2024ag_Wireline_Ethernet/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Homeoffice2024a_Wireline_Ethernet/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Homeoffice2024c_Mobile_LTE/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Homeoffice2024e_MacOS_WiFi/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Homeoffice2025cg_Mobile_LTE/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Test2023a_Wireline_Ethernet/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Test2023c_Mobile_LTE/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Test2023e_MacOS_Wifi/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Test2024ag_Wireline_Ethernet/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Test2024a_Wireline_Ethernet/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Test2024cg_Mobile_LTE/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Test2024c_Mobile_LTE/pcaps',
    '/media/solana/Backup Plus/Data/dvc_data/Test2024e_MacOS_Wifi/pcaps'   
    ]


@click.group()
def cli():
    pass

@cli.command(name='tr')
def main():
    failed_files = []
    for input_file_path in data_path: 
        # Get the relative path structure after 'pcaps' directory
        pcap_path = Path(input_file_path)           
        files = list(pcap_path.glob('**/*.pcap'))
        total_files = len(files)
        for i, file in enumerate(files):
            print(f'[{i}/{total_files}] -> {file} ')
            head, tail = os.path.split(file)
            head = head.replace('pcaps', 'features')
            if not os.path.exists(head):
                os.makedirs(head)
            tail = tail.replace('.pcap', '.csv')
            features_file_path = Path(head, tail)
            
            try:
                subprocess.run(['/home/solana/projects/parser/packet-parsing/tools/tranalyzer2-0.9.3/tranalyzer2/build/tranalyzer', '-r', str(file), '-w', 'output'])
            except Exception as e:
                failed_files.append(str(file))
                continue
            
            df = pd.read_table('output_flows.txt', sep='\t')
            df['firstTimeStamp'] = pd.to_datetime(df['timeFirst'], unit='s').dt.strftime('%d/%m/%Y %H:%M:%S')
            df['lastTimeStamp'] = pd.to_datetime(df['timeLast'], unit='s').dt.strftime('%d/%m/%Y %H:%M:%S')
            df['data_source'] = head.split('/')[6]
            df['traffic_type'] = head.split('/')[8]
            df['application_type'] = head.split('/')[9]
            df.to_csv(features_file_path)
    print(failed_files)


if __name__ == '__main__':
    cli()