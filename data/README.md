The network traffic is held in the csv files of this folder, organized by day of the week and the network of the system, whether public network or private network. 

# Feature Description

There are 76 features that were extracted by the [CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt) in addition to 7 fields (1-7 in the table below) that identify a communication flow between 2 systems. Our labeling process has added 2 columns - Activity and Stage, giving users the information on malicious activities and under which stage they fall. All these accumulate into 85 columns in our flow files in the csv folder on this repo. The below table lists the 85 columns in order. 

| Header Column Name | Header Column Description |
| ------ | -------- | 
| Flow ID | Flow Identifier |
| Src IP | Source IP Address |
| Src Port | Source Port |
| Dst IP | Destination IP Address | 
| Dst Port | Destination Port |
| Protocol | Communication Protocol |
| Timestamp | Timestamp of the start of the flow |
| Flow Duration | 	Flow duration  |
| Total Fwd Packet | 	Total packets in the forward direction  |
| Total Bwd packets | 	Total packets in the backward direction  |
| Total Length of Fwd Packet | 	Total size of packet in forward direction  |
| Total Length of Bwd Packet | 	Total size of packet in backward direction  |
| Fwd Packet Length Max | 	Maximum size of packet in forward direction  |
| Fwd Packet Length Min | 	Minimum size of packet in forward direction  |
| Fwd Packet Length Mean | 	Average size of packet in forward direction  |
| Fwd Packet Length Std | 	Standard deviation size of packet in forward direction  |
| Bwd Packet Length Max | 	Maximum size of packet in backward direction  |
| Bwd Packet Length Min | 	Minimum size of packet in backward direction  |
| Bwd Packet Length Mean | 	Mean size of packet in backward direction  |
| Bwd Packet Length Std | 	Standard deviation size of packet in backward direction  |
| Flow Bytes/s | 	flow byte rate that is number of packets transferred per second  |
| Flow Packets/s | 	flow packets rate that is number of packets transferred per second  |
| Flow IAT Mean | 	Average time between two flows    |
| Flow IAT Std | 	Standard deviation time two flows  |
| Flow IAT Max | 	Maximum time between two flows  |
| Flow IAT Min | 	Minimum time between two flows  |
| Fwd IAT Total | 	Total time between two packets sent in the forward direction  |
| Fwd IAT Mean | 	Mean time between two packets sent in the forward direction  |
| Fwd IAT Std | 	Standard deviation time between two packets sent in the forward direction  |
| Fwd IAT Max | 	Maximum time between two packets sent in the forward direction  |
| Fwd IAT Min | 	Minimum time between two packets sent in the forward direction    |
| Bwd IAT Total | 	Total time between two packets sent in the backward direction  |
| Bwd IAT Mean | 	Mean time between two packets sent in the backward direction  |
| Bwd IAT Std | 	Standard deviation time between two packets sent in the backward direction  |
| Bwd IAT Max | 	Maximum time between two packets sent in the backward direction  |
| Bwd IAT Min | 	Minimum time between two packets sent in the backward direction  |
| Fwd PSH Flags | 	Number of times the PSH flag was set in packets travelling in the forward direction (0 for UDP)  |
| Bwd PSH Flags | 	Number of times the PSH flag was set in packets travelling in the backward direction (0 for UDP)  |
| Fwd URG Flags | 	Number of times the URG flag was set in packets travelling in the forward direction (0 for UDP)  |
| Bwd URG Flags | 	Number of times the URG flag was set in packets travelling in the backward direction (0 for UDP)  |
| Fwd Header Length | 	Total bytes used for headers in the forward direction  |
| Bwd Header Length | 	Total bytes used for headers in the forward direction  |
| Fwd Packets/s | 	Number of forward packets per second  |
| Bwd Packets/s | 	Number of backward packets per second  |
| Packet Length Min | 	Minimum length of a flow  |
| Packet Length Max | 	Maximum length of a flow  |
| Packet Length Mean | 	Mean length of a flow  |
| Packet Length Std | 	Standard deviation length of a flow  |
| Packet Length Variance | 	Minimum inter-arrival time of packet  |
| FIN Flag Count | 	Number of packets with FIN  |
| SYN Flag Count | 	Number of packets with SYN  |
| RST Flag Count | 	Number of packets with RST  |
| PSH Flag Count | 	Number of packets with PUSH  |
| ACK Flag Count | 	Number of packets with ACK  |
| URG Flag Count | 	Number of packets with URG  |
| CWR Flag Count | 	Number of packets with CWE  |
| ECE Flag Count | 	Number of packets with ECE  |
| Down/Up Ratio | 	Download and upload ratio  |
| Average Packet Size | 	Average size of packet  |
| Fwd Segment Size Avg | 	Average size observed in the forward direction  |
| Bwd Segment Size Avg | 	Average size observed in the backward direction  |
| Fwd Bytes/Bulk Avg | 	Average number of bytes bulk rate in the forward direction    |
| Fwd Packet/Bulk Avg | 	Average number of packets bulk rate in the forward direction    |
| Fwd Bulk Rate Avg | 	Average number of bulk rate in the forward direction    |
| Bwd Bytes/Bulk Avg | 	Average number of bytes bulk rate in the backward direction    |
| Bwd Packet/Bulk Avg | 	Average number of packets bulk rate in the backward direction    |
| Bwd Bulk Rate Avg | 	Average number of bulk rate in the backward direction    |
| Subflow Fwd Packets | 	The average number of packets in a sub flow in the forward direction    |
| Subflow Fwd Bytes | 	The average number of bytes in a sub flow in the forward direction  |
| Subflow Bwd Packets | 	The average number of packets in a sub flow in the backward direction  |
| Subflow Bwd Bytes | 	The average number of bytes in a sub flow in the backward direction  |
| FWD Init Win Bytes | 	Number of bytes sent in initial window in the forward direction  |
| Bwd Init Win Bytes | 	Number of bytes sent in initial window in the backward direction  |
| Fwd Act Data Pkts | 	Number of packets with at least 1 byte of TCP data payload in the forward direction  |
| Fwd Seg Size Min | 	Minimum segment size observed in the forward direction  |
| Active Mean | 	Mean time a flow was active before becoming idle  |
| Active Std | 	Standard deviation time a flow was active before becoming idle  |
| Active Max | 	Maximum time a flow was active before becoming idle  |
| Active Min | 	Minimum time a flow was active before becoming idle  |
| Idle Mean | 	Mean time a flow was idle before becoming active  |
| Idle Std | 	Standard deviation time a flow was idle before becoming active  |
| Idle Max | 	Maximum time a flow was idle before becoming active  |
| Idle Min | 	Minimum time a flow was idle before becoming active  |
| Activity | Activity this flow represents |
| Stage |  Stages this flow falls under |