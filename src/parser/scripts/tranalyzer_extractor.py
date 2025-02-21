import subprocess
import pandas as pd
from pathlib import Path
import click
import os

@click.group()
def cli():
    pass

@cli.command(name='tr')
@click.argument('input_file_path', type=str)
@click.argument('output_file_path', type=Path)
def main(input_file_path, output_file_path):
    print(output_file_path)
    # output_file_path = Path(output_file_path, 'output')
    subprocess.run(['t2', '-r', input_file_path, '-w', output_file_path])

    data = pd.read_table('output_flows.txt', sep='\t')
    data['firstTimeStamp'] = pd.to_datetime(data['timeFirst'], unit='s').dt.strftime('%d/%m/%Y %H:%M:%S')
    data['lastTimeStamp'] = pd.to_datetime(data['timeLast'], unit='s').dt.strftime('%d/%m/%Y %H:%M:%S')
    output_file_path = Path(output_file_path, os.path.basename(input_file_path).replace('.pcap', '.csv'))
    data.to_csv(output_file_path)

if __name__ == '__main__':
    cli()