import os
import magic
import pandas as pd
from collections import Counter
from scipy import stats
from math import log2
import pyshark
import nest_asyncio
from tqdm import tqdm
import sys
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import BaggingClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import numpy as np
from tqdm import tqdm
import pickle





def byte_entropy(labels):
  ent = stats.entropy(list(Counter(labels).values()), base=2)
  if len(labels)<256:
    return ent*8/log2(len(labels))
  else:
    return ent




def process_payload(data, is_hex=True):
  """
  returns size and normalized entropy for the hex data
  """
  if is_hex:
    payload_bytes = bytes.fromhex("".join(data.split(":")))
  else:
    payload_bytes = data.encode()
  payload_size = len(payload_bytes)
  payload_entropy = byte_entropy(payload_bytes)
  return payload_size, payload_entropy



def process_packet(packet):
  highest_layer = packet.highest_layer
  packet_type = packet.transport_layer
  layer_names = list(map(lambda x: x.layer_name, packet.layers))
  src_ip = None
  dst_ip = None
  src_port = -1
  dst_port = -1
  payload_size = 0
  payload_entropy = 0
  timestamp = float(packet.sniff_timestamp)
  packet_size = int(packet.length)
  small_packet = int(packet_size < 100)
  if packet_type:  ##contains an IP layer
    src_ip = packet.ip.src
    dst_ip = packet.ip.dst
    if packet_type == 'TCP':
      src_port = packet.tcp.srcport
      dst_port = packet.tcp.dstport
      
      if 'data' in layer_names:
        payload_size, payload_entropy = process_payload(packet.tcp.payload)
        
    elif packet_type == 'UDP':
      src_port = packet.udp.srcport
      dst_port = packet.udp.dstport
      if 'data' in layer_names:
        payload_size, payload_entropy = process_payload(packet.data.data)
  elif 'icmp' in layer_names:
    try:
      payload_size, payload_entropy = process_payload(packet.icmp.data)
    except AttributeError:
      payload_size, payload_entropy = 0,0
    packet_type = 'ICMP'
  elif 'arp' in layer_names:
    dst_ip = packet.arp.dst_proto_ipv4
    src_ip = packet.arp.src_proto_ipv4
    packet_type = 'ARP'
  if 'dns' in layer_names:
    payload_size, payload_entropy = process_payload(packet.dns.qry_name,False)
  return src_ip, src_port, dst_ip, dst_port, packet_type, timestamp, packet_size ,highest_layer, payload_entropy, payload_size, small_packet



capture_dump = pyshark.FileCapture('/home/ragnar/Documents/Workspace/Opensource/p2p-botnet-detector/Botnet_Detection_Dataset/Benign/p2pbox1/p2pbox1.2011032611.pcap.clean.pcap')
packet  = capture_dump.next()

src_ip, src_port, dst_ip, dst_port, packet_type, timestamp, packet_size ,highest_layer, payload_entropy, payload_size, small_packet = process_packet(packet)
print(src_ip, src_port, dst_ip, dst_port, packet_type, timestamp, packet_size ,highest_layer, payload_entropy, payload_size, small_packet)
