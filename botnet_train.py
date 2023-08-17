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

FLOW = {}

def get_pcaps(base_path):
  pcap_list = []
  for path, dir, files in os.walk(base_path):
    for file in files:
      file_name = os.path.join(path, file)
      magic_mime = magic.from_file(file_name, mime=True)
      if magic_mime == 'application/vnd.tcpdump.pcap' or magic_mime == 'application/octet-stream':
        pcap_list.append(file_name)
  return pcap_list


def byte_entropy(labels):
  ent = stats.entropy(list(Counter(labels).values()), base=2)
  if len(labels)<256:
    return ent*8/log2(len(labels))
  else:
    return ent


class Flow:
  def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol):

    self.src_ip = src_ip     
    self.src_port = src_port
    self.dst_ip = dst_ip
    self.dst_port = dst_port
    self.protocol = protocol

    self.total_data = 0
    self.sent_packets = 0
    self.recv_packets = 0
    self.sent_data = 0
    self.recv_data = 0
    self.num_small_packets = 0

    self.total_sent_payload = 0
    self.total_recv_payload = 0
    self.max_payload_size = 0
    self.max_payload_entropy = 0
    self.min_payload_size = 0
    self.min_payload_entropy = 0
    self.highest_protocols = set()
    self.last_timestamp_sent = None
    self.start_timestamp_sent = None
    self.last_timestamp_recv = None
    self.start_timestamp_recv = None
    
    self.total_time = None
    self.all_payload = b''
    self.net_entropy = 0
    self.average_payload_size = 0
    self.average_packet_size_per_sec = 0
    self.average_packet_per_sec = 0
    self.average_packet_length = 0
    self.incoming_outgoing_ratio = 0
    self.label = 0



def process_payload(data, is_hex=True):
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
  if packet_type:
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
  
def fill_flow(packet,label):
  src_ip, src_port, dst_ip, dst_port, packet_type, timestamp, packet_size ,highest_layer, payload_entropy, payload_size, small_packet = process_packet(packet)
  flow_key = (src_ip, src_port, dst_ip, dst_port, packet_type)
  flow_key_rev = (dst_ip, dst_port, src_ip, src_port, packet_type)
  
  flow = FLOW.get(flow_key, Flow(*flow_key))
  flow.total_data += packet_size
  flow.sent_data += packet_size
  flow.max_payload_size = max(payload_size, flow.max_payload_size)
  flow.max_payload_entropy = max(payload_entropy, flow.max_payload_entropy)
  flow.min_payload_size = min(payload_size, flow.max_payload_size)
  flow.min_payload_entropy = min(payload_entropy, flow.max_payload_entropy)
  flow.total_sent_payload += payload_size
  flow.sent_packets += 1
  flow.num_small_packets+=small_packet
  flow.highest_protocols.add(highest_layer)
  flow.label = label
  
  if not flow.start_timestamp_sent:
    flow.start_timestamp_sent = timestamp
  flow.last_timestamp_sent = timestamp
  FLOW[flow_key] = flow

  flow_rev = FLOW.get(flow_key_rev, Flow(*flow_key_rev))
  flow_rev.total_data += packet_size
  flow_rev.recv_data += packet_size
  flow_rev.total_recv_payload += payload_size
  flow_rev.recv_packets += 1
  flow_rev.highest_protocols.add(highest_layer)
  if not flow_rev.start_timestamp_recv:
    flow_rev.start_timestamp_recv = timestamp
  flow_rev.last_timestamp_recv = timestamp
  flow_rev.label = label
  FLOW[flow_key_rev] = flow_rev


def get_num_packets(path):
  command = "tshark -r {} | wc -l"
  data = os.popen(command.format(path)).read()
  return int(data.strip())


def filter_data(pcap_path, ip_list, csv_path, label=0):
  num_packets = get_num_packets(pcap_path)
  nest_asyncio.apply()
  capture_dump = pyshark.FileCapture(pcap_path)
  print("Number of packets found: {}".format(num_packets))
  capture_dump.keep_packets = False ##very memory consuming, very important
  for i in tqdm(range(num_packets), desc = "processing pcap {}".format(pcap_path), ascii=False):
    try:
      packet  = capture_dump.next()
      fill_flow(packet,label)
    except Exception as e:
      print(e)
  with open(csv_path,'w') as output_csv:
    header = "src_ip,src_port,dst_ip,dst_port,protocol,total_data, sent_packets,recv_packets,sent_data,recv_data,total_sent_payload,total_recv_payload,max_payload_size,max_payload_entropy,min_payload_size,min_payload_entropy,net_entropy,average_payload_size,average_packet_length,average_packet_per_sec,average_packet_size_per_sec,num_protocols,total_time,incoming_outgoing_ratio,num_small_packets,label\n"
    output_csv.write(header)
    for key in tqdm(FLOW.keys(), desc = "saving to {}".format(csv_path), ascii=False ):
      m = FLOW[key]
      m.post_processing()
      output_csv.write(m.to_csv())

def clean_dataset(df):
    assert isinstance(df, pd.DataFrame), "df needs to be a pd.DataFrame"
    df.fillna(0,inplace=True)
    indices_to_keep = ~df.isin([np.nan, np.inf, -np.inf]).any(1)
    return df[indices_to_keep].astype(np.float64)


def train(model_name):
  p2pbox1_pcaps = get_pcaps("Botnet_Detection_Dataset/Benign/p2pbox1")
  p2pbox2_pcaps = get_pcaps("Botnet_Detection_Dataset/Benign/p2pbox2")
  torrent_pcaps = get_pcaps("Botnet_Detection_Dataset/Benign/torrent")
  storm_pcaps = get_pcaps("Botnet_Detection_Dataset/Botnet/storm")
  vinchua_pcaps = get_pcaps("Botnet_Detection_Dataset/Botnet/vinchuca")
  zeus_pcaps = get_pcaps("Botnet_Detection_Dataset/Botnet/zeus")

  files_benign = p2pbox1_pcaps+p2pbox2_pcaps+torrent_pcaps
  files_botnet = storm_pcaps+vinchua_pcaps+zeus_pcaps


  if not os.path.exists("filtered_data"):
    os.mkdir("filtered_data")

  for file in files_botnet:
    base_name = os.path.basename(file)
    filter_data(file, [], os.path.join("filtered_data", base_name+".csv"), label=1)
    FLOW.clear()

  for file in files_benign:
    base_name = os.path.basename(file)
    filter_data(file, [], os.path.join("filtered_data", base_name+".csv"), label=0)
    FLOW.clear()

  df_all = None
  for file in tqdm(os.listdir("filtered_data"), ascii=False):
    df = pd.read_csv(os.path.join("filtered_data",file))
    if 'label' not in df.columns:
      print(file)
    if type(df_all) == type(None):
      df_all = df
    else:
      df_all = df_all.append(df, ignore_index = True)

  with open('training.csv','w') as out_csv:
    out_csv.write(df_all.to_csv(index = False))


  features = clean_dataset(df[df.columns[5:-1]])
  flows = df[df.columns[0:5]]
  y = df['label']
  X_train, X_test, y_train, y_test = train_test_split(features, y, test_size=0.2)
  dtc = DecisionTreeClassifier()
  bag=BaggingClassifier(base_estimator=dtc, n_estimators=100, bootstrap=True)
  bag.fit(X_train, y_train) # Fit the model using train data
  print(bag.score(X_test,y_test)) # Get the accuracy of test data
  print(precision_recall_fscore_support(bag.predict(X_test),y_test))
  with open(model_name,'wb') as model_file:
    pickle.dump(bag, model_file)


if __name__ == "__main__":

  if len(sys.argv)==3:
    if sys.argv[1]=="train":
      model_name = sys.argv[2]
      train(model_name)
    else:
      exit(1)

  else:
    exit(1)
