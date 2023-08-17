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
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import numpy as np
from tqdm import tqdm
import pickle


FLOW = {}

def byte_entropy(labels):
  ent = stats.entropy(list(Counter(labels).values()), base=2)
  if len(labels)<256:
    return ent*8/log2(len(labels))
  else:
    return ent


class HostInfo:
  def __init__(self, ipv4_address):
    self.ip = ipv4_address # string (can be converted to 32 bit int if needed)
    self.src_ports = set()  #list of host ports i.e the ports where it serves as source
    self.dst_ports = set() # list of dest ports i.e the ports where it serves as destination
    self.ip_recieved_from = set()
    self.ip_sent_to = set()
    self.protocols = set() # protocols used by the host
    self.total_data_sent = 0
    self.total_data_recv = 0
    self.total_payload = 0  # payload only in data
    self.num_udp_packets_recv = 0
    self.num_udp_packets_sent = 0
    self.num_tcp_packets_recv = 0
    self.num_tcp_packets_sent = 0
    self.total_packets = 0

  def ipv4_to_int(ip_addr):
    vals = map(int, ip_addr.split('.'))
    return sum(x*256**y for x,y in zip(vals,(3,2,1,0)))

  def __repr__(self):
    return self.ip

  def __hash__(self):
    return hash(repr(self))

  def process_packet(self, packet):
    packet_type = packet.transport_layer
    layer_names = list(map(lambda x: x.layer_name, packet.layers))
    if packet_type:
      if packet.ip.src == self.ip:
        self.protocols.add(packet_type)
        self.ip_sent_to.add(packet.ip.dst)
        self.total_data_sent += packet.length
        self.total_packets += 1
        if packet_type == 'TCP':
          self.src_ports.add(packet.tcp.srcport)
          self.num_tcp_packets_sent += 1
          if 'data' in layer_names:
            self.total_payload += len(packet.tcp.payload)
        elif packet_type == 'UDP':
          self.src_ports.add(packet.udp.srcport)
          self.num_udp_packets_sent += 1
          if 'data' in layer_names:
            self.total_payload += len(packet.data.data)
      elif packet.ip.dst == self.ip:
        self.protocols.add(packet_type)
        self.ip_received_from.add(packet.ip.src)
        self.total_data_recv += packet.length
        self.total_packets += 1
        if packet_type == 'TCP':
          self.dst_ports.add(packet.tcp.dstport)
          self.num_tcp_packets_recv += 1
          if 'data' in layer_names:
            self.total_payload += len(packet.tcp.payload)
        elif packet_type == 'UDP':
          self.dst_ports.add(packet.udp.dstport)
          self.num_udp_packets_recv += 1
          if 'data' in layer_names:
            self.total_payload += len(packet.data.data)
    elif 'arp' in layer_names:
      if packet.arp.src_proto_ipv4 == self.ip:
        self.protocols.add('ARP')
        self.ip_sent_to.add(packet.arp.dst_proto_ipv4)
        self.total_data_sent += packet.length
        self.total_packets += 1
      elif packet.arp.dst_proto_ipv4 == self.ip:
        self.protocols.add('ARP')
        self.ip_received_from.add(packet.arp.src_proto_ipv4)
        self.total_data_recv += packet.length
        self.total_packets += 1
    elif 'icmp' in layer_names:
      if packet.ip.src == self.ip:
        self.protocols.add('ICMP')
        self.ip_sent_to.add(packet.ip.dst)
        self.total_data_sent += packet.length
        self.src_ports.add(packet.udp.srcport)
        self.total_packets += 1
      elif packet.ip.dst == self.ip:
        self.protocols.add('ICMP')
        self.ip_received_from.add(packet.ip.src)
        self.total_data_recv += packet.length
        self.dst_ports.add(packet.tcp.dstport)
        self.total_packets += 1


def min_none(a,b):
  if not a:
    return b
  if not b:
    return a
  return min(a,b)

def max_none(a,b):
  if not a:
    return b
  if not b:
    return a
  return max(a,b)

# key src ip, src port, dst ip, dst port, protocol
class Flow:
  """
  Class to represent flow information (5-tuple)
  """
  def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol):
    """
    initialize the source, destination host, ports and protocol
    """
    self.src_ip = src_ip     #ip of source of flow
    self.src_port = src_port # port used by source of flow
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
    #post processing data
    self.total_time = None
    self.all_payload = b''
    self.net_entropy = 0
    self.average_payload_size = 0
    self.average_packet_size_per_sec = 0
    self.average_packet_per_sec = 0
    self.average_packet_length = 0
    self.incoming_outgoing_ratio = 0
    self.label = 0


  def __repr__(self):
    return "{0},{1},{2},{3},{4}".format(self.src_ip,self.src_port,self.dst_ip,self.dst_port,self.protocol) 

  def __hash__(self):
    return hash(repr(self))

  def post_processing(self):
    self.total_time = max_none(self.last_timestamp_recv, self.last_timestamp_sent) - min_none(self.start_timestamp_recv, self.start_timestamp_sent)
    if self.all_payload:
      self.net_entropy = byte_entropy(self.all_payload)
    if self.total_time:
      self.average_packet_size_per_sec = self.sent_data/self.total_time
      self.average_packet_per_sec = self.sent_packets/self.total_time
    if self.sent_packets:
      self.average_payload_size = self.total_sent_payload/(self.sent_packets)
    self.average_packet_length = self.total_data/(self.sent_packets+self.recv_packets)
    if self.sent_data !=0:
      self.incoming_outgoing_ratio = self.recv_data/self.sent_data
    else:
      self.incoming_outgoing_ratio = self.recv_data
    
  def to_csv(self):
    return "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21},{22},{23},{24},{25}\n".format(
      self.src_ip, 
      self.src_port, 
      self.dst_ip, 
      self.dst_port, 
      self.protocol, 
      self.total_data,
      self.sent_packets,
      self.recv_packets,
      self.sent_data,
      self.recv_data,
      self.total_sent_payload,
      self.total_recv_payload,
      self.max_payload_size,
      self.max_payload_entropy,
      self.min_payload_size,
      self.min_payload_entropy,
      self.net_entropy,
      self.average_payload_size,
      self.average_packet_length,
      self.average_packet_per_sec,
      self.average_packet_size_per_sec,
      len(self.highest_protocols),
      self.total_time,
      self.incoming_outgoing_ratio,
      self.num_small_packets,
      self.label
      )

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



def format_flow(flow):
  return "{}:{} -> {}:{} ; {}\n".format(*flow)

def clean(df, pred,indices, output_path):
  h1 = Counter([i[0] for i in pred])
  h2 = Counter([i[2] for i in pred])
  n = len(pred)
  N = len(df)
  output_flows = []
  print(n,N,n/N)
  thresh = n/200
  output_file = open(output_path, "w")
  host = h1.most_common(1)[0][0]
  botnets = set( i for i in h1  if h1[i] > thresh ).intersection( i for i in h2  if h2[i] > thresh )
  if botnets:
    botnets.remove(host)
  for predic in pred:
    if predic[4]== 'UDP' or predic[4]=='TCP':
      if predic[0] in botnets or predic[2] in botnets:
        output_flows.append(predic)

  lb = max(len(botnets),1)
  if n/N < 0.2 or len(output_flows)/lb < 10:
    output_file.write("No Botnets detected\n")
  else:
    output_file.write("----------Detected Botnet Hosts----------\n")
    for botnet in botnets:
      output_file.write(botnet+"\n")
    output_file.write(host)
    output_file.write("----------Malicious Flows----------\n")
    for flow in output_flows:
      output_file.write(format_flow(flow))
  output_file.close()
  print("output written to {}".format(output_path))


def detection(pcap_path, csv_path):
  filter_data(pcap_path,[],csv_path)
  df = pd.read_csv(csv_path)
  features = clean_dataset(df[df.columns[5:-1]])
  model_name = "extracted_feature.csv"
  with open(model_name,'rb') as model_file:
    model = pickle.load(model_file)
  flows = df[df.columns[0:5]]
  predictions = model.predict(features)
  indices = []
  botnet_flows = []
  for i in range(len(predictions)):
    if predictions[i] == 1:
      indices.append(i)
      botnet_flows.append(list(flows.iloc[i]))
  return df, botnet_flows, indices


def main(pcap_path, csv_path,output_path):
  a,b,c = detection(pcap_path, csv_path)
  clean(a,b,c,output_path)


if __name__ == "__main__":

  if len(sys.argv)==2:
    if os.path.exists(sys.argv[1]):
      csv_path = "extracted_features.csv"
      output_path = "output.txt"
      main(sys.argv[1],csv_path,output_path)

    else:
      print("file not found")
      exit(1)

  else:
    exit(1)
