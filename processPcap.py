import logging
import pickle
from pathlib import Path
import glob

import multiprocessing as MP
import subprocess
import numpy as np
import pandas as pd
import os
import time
from tqdm import tqdm

def contructTsharkCommand(filename,tsharkOptions,nomePcap):
    
    #pasta = "/media/uelinton/HD Local/LINUX/2020/PCAPS/tshark/"
    #pasta = "/home/uelinton/Andressa/PRIVATE-method/pcaps/tshark/"
    pasta = "/home/mcoelho/FAPESP/pcaps/tshark/"
    command = 'tshark -r '+"\"" +filename+ "\""' '
    for eachstring in tsharkOptions:
        command = command + eachstring + ' '
    
    #construct output filename
    outfilename = filename.split('/')

    #cria csv para cada pcap lido no diretorio dos packetdata
    outfilename = pasta + outfilename[len(outfilename)-1] + '.csv'

    #comando para cada pcap
    command += "> \"" +outfilename+"\""
    
    return (command,outfilename)


TSHARK_OPT = ["-t ad",
            "-T fields",
            "-E separator=,",
            "-e _ws.col.Time -e ip.src -e ip.dst -e ip.proto -e tcp.len -e udp.length -e eth.src -e eth.dst",
            "-e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport",
            ]

PACKET_COLUMNS =  ['timestamp', 'ip_src', 'ip_dst', 'proto','len_tcp','len_udp', 'mac_src', 'mac_dst',
 'tcp_srcport', 'tcp_dstport', 'udp_srcport', 'udp_dstport']

# execute a shell command as a child process
def executeCommand(command, outfilename, rotulos, salveFilter,rotul):
    sem.acquire()

    subprocess.call(command, shell=True, stdout=subprocess.PIPE)
    df = pd.read_csv(outfilename, error_bad_lines=False, warn_bad_lines=False)
    df.columns = PACKET_COLUMNS

    df.fillna(0, inplace = True)
    
    df['src_port'] = df['tcp_srcport'] + df['udp_srcport']
    df['dst_port'] = df['tcp_dstport'] + df['udp_dstport']

    # delete packets with size equal to 0
    df['len'] = df['len_tcp'] + df['len_udp']
    df = df[df['len'] !=0]

    df = df.drop(columns=['len_tcp','len_udp','tcp_srcport', 'tcp_dstport', 'udp_srcport', 'udp_dstport'])

    # No broadcast
    df.drop(df[(df['mac_dst'] == 'ff:ff:ff:ff:ff:ff') | (df['ip_dst'] == '255.255.255.255')].index, inplace=True)

    # add o rotulo do device por meio do mac (usa arq csv)
    df['device_src_name'] = df['mac_src'].map(rotul.set_index('mac')['device_name'])
    #df['device_dst_name'] = df['mac_dst'].map(rotul.set_index('mac')['device_name'])

    #df['type'] = rotulos
    df.to_csv(salveFilter+rotulos+'.csv', index=False)
    print('done writing packet to : ' + salveFilter+rotulos+'.csv') 
    sem.release()
    #return merge

#pcap_path = Path("/home/uelinton/FAPESP/FCC-NovoDataset/iscx-analysis/datasets/pcaps")
#pcap_path = Path("/media/uelinton/HD Local/LINUX/2020/PCAPS")
#pcap_path = Path("/home/uelinton/Andressa/PRIVATE-method/pcaps/pcapsTeste")
pcap_path = Path("/home/mcoelho/FAPESP/pcaps")

#salveFilter = "/media/uelinton/HD Local/LINUX/2020/PCAPS/csvfilter/"
#salveFilter = "/home/uelinton/Andressa/PRIVATE-method/pcaps/csvfilter/"
salveFilter = "/home/mcoelho/FAPESP/pcaps/csvfilter/"

rotul = pd.read_csv("device_list.csv")

sem = MP.Semaphore(1)
tasks = []
merge = []

for i_pcap_file, pcap_file in enumerate(pcap_path.glob("*.pcap")):
    print(pcap_file)
    (command, outfilename) = contructTsharkCommand(str(pcap_file), TSHARK_OPT, pcap_file.stem)
    print(command)
    task = MP.Process(target=executeCommand, args=(command, outfilename, pcap_file.stem, salveFilter,rotul))
    task.start()
    tasks.append(task)

for task in tqdm(tasks, unit="pcap_file"):
    task.join()

#inputfile = Path("/home/uelinton/Andressa/PRIVATE-method/pcaps/csvfilter/")
inputfile = Path("/home/mcoelho/FAPESP/pcaps/csvfilter/")

for filename in tqdm(inputfile.glob("*.csv"), unit = "CSVs"): ## percorre o vetor de csv
    df = pd.read_csv(filename)
    df = df.drop(columns = ['ip_src', 'ip_dst', 'src_port', 'dst_port'])
    merge.append(df)

df_total = pd.concat(merge, axis = 0, ignore_index=True) ## concatena todos csv num dataframe apenas
df_total.to_csv('df_total.csv', index=False)
