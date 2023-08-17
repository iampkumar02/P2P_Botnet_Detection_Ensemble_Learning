# Peer to Peer Botnet Detection

This project aims to detect infected hosts and identify malicious traffic associated with botnets from network dumps captured on a machine.

## Dependencies

The program is tested on Python 3.8, but it should work on versions above 3.6 as well. To install the dependencies, use the following commands:
```
sudo apt-get install wireshark
sudo apt-get install -y tshark
sudo apt-get install libmagic-dev
pip3 install -r requirements.txt
```


## Structure

### [botnetdetect.py](botnetdetect.py)

This is the main program responsible for detecting botnets and training the Machine Learning model for botnet detection.

#### Usage

##### Botnet Detection

Botnet detection works on a pre-captured pcap file:

`python3 botnet-detect.py <path to pcap file>`

Processes pcap file to produce `extracted_features.csv` which contains the features extracted from the pcap
> NOTE: feature extraction is slow depending upon the size of input pcap (approx 1 minute to process 10MB)

results are stored in `output.txt`

Analysis of more than one pcap files yet to be done, although the functionality has been written.  

##### Train model
`python3 botnet_train.py train model_name`
> Assumption: The current directory contains training data in directory `Botnet_Detection_Dataset`

Generates filtered csv files in `filtered_data` directory in current working directory
All the csv files will be further collected in a `training.csv`

#### Result format
The results are stored in `output.txt`  
If no botnet is detected, the result would be 
**No Botnets detected** in a single line
Otherwise, the contents of output.txt would be 

```
----------Detected Botnet Hosts----------
host1  
host2  
...  
host n  
----------Malicious Flows----------
source ip1:source port1 -> destination ip1:destination port1 ; protocol  
source ip2:source port2 -> destination ip2:destination port2 ; protocol  
...  
source ipn:source portn -> destination ipn:destination portn ; protocol  
```
