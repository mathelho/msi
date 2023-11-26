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

def constructTsharkCommand(filename, tsharkOptions, nomePcap):
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

TSHARK_OPT = ["-t e",
              "-T fields",
              "-E separator=,",
              "-e frame.time_epoch -e tcp.len -e udp.length -e eth.src -e eth.dst",
              '-Y "(ip.proto==6)||(ip.proto==17)"']

PACKET_COLUMNS = ['timestamp', 'len_tcp', 'len_udp', 'mac_src', 'mac_dst']

# execute a shell command as a child process
def executeCommand(command, outfilename, rotulos, salveFilter,rotul):
    sem.acquire()

    subprocess.call(command, shell=True, stdout=subprocess.PIPE)
    df = pd.read_csv(outfilename, error_bad_lines=False, warn_bad_lines=False)
    df.columns = PACKET_COLUMNS

    df.fillna(0, inplace = True)
    
    #df['src_port'] = df['tcp_srcport'] + df['udp_srcport']
    #df['dst_port'] = df['tcp_dstport'] + df['udp_dstport']

    # delete packets with size equal to 0
    df['len'] = df['len_tcp'] + df['len_udp']
    df = df[df['len'] !=0]

    df = df.drop(columns=['len_tcp','len_udp'])

    # No broadcast
    #df.drop(df[(df['mac_dst'] == 'ff:ff:ff:ff:ff:ff') | (df['ip_dst'] == '255.255.255.255')].index, inplace=True)
    df.drop(df[(df['mac_dst'] == 'ff:ff:ff:ff:ff:ff')].index, inplace=True)

    # add o rotulo do device por meio do mac (usa arq csv)
    df['device_src_name'] = df['mac_src'].map(rotul.set_index('mac')['device_name'])
    #df['device_dst_name'] = df['mac_dst'].map(rotul.set_index('mac')['device_name'])

    #df['type'] = rotulos
    df.to_csv(salveFilter+rotulos+'.csv', index=False)
    print('done writing packet to : ' + salveFilter+rotulos+'.csv') 
    sem.release()
    #return merge

pcap_path = Path("/home/mcoelho/FAPESP/pcaps")
salveFilter = "/home/mcoelho/FAPESP/pcaps/csvfilter/"

rotul = pd.read_csv("device_list.csv")
rotul2 = pd.read_csv("new_device_list.csv")

sem = MP.Semaphore(1)
tasks = []
merge = []

# adiciona a task de rotular os devices do pcap falso, utilizando o novo device_list
false_pcap_file = Path("/home/mcoelho/FAPESP/pcapsFalsos/600.pcap")
(command, outfilename) = constructTsharkCommand(str(false_pcap_file), TSHARK_OPT, false_pcap_file.stem)
task = MP.Process(target=executeCommand, args=(command, outfilename, false_pcap_file.stem, salveFilter,rotul2))
task.start()
tasks.append(task)

# dá continuidade, agora adicionando as tasks de extração dos pcaps "verdadeiros"
for i_pcap_file, pcap_file in enumerate(pcap_path.glob("*.pcap")):
    print(pcap_file)
    (command, outfilename) = constructTsharkCommand(str(pcap_file), TSHARK_OPT, pcap_file.stem)
    print(command)
    print(outfilename)
    task = MP.Process(target=executeCommand, args=(command, outfilename, pcap_file.stem, salveFilter,rotul))
    task.start()
    tasks.append(task)

for task in tqdm(tasks, unit="pcap_file"):
    task.join()

inputfile = Path("/home/mcoelho/FAPESP/pcaps/csvfilter/")

# move o 600.csv para a raiz, para nao entrar no dataframe final, separando os pcaps verdadeiros do falso
Path("/home/mcoelho/FAPESP/pcaps/csvfilter/600.csv").rename("/home/mcoelho/FAPESP/600.csv")

for filename in tqdm(inputfile.glob("*.csv"), unit = "CSVs"): ## percorre o vetor de csv
    df = pd.read_csv(filename)
    merge.append(df)

df_total = pd.concat(merge, axis = 0, ignore_index=True) ## concatena todos csv num dataframe apenas
df_total.to_csv('df_total.csv', index=False)