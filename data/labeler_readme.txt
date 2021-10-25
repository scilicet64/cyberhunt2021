#Notes on the labeling made. 
#python [script_name_with_extension] [file_path] [file_name_without_extension] [src_ip] [start_time] [end_time] [dst_port]

python labeler.py csv\csv enp0s3-monday.pcap_Flow
python labeler.py csv\csv enp0s3-monday-pvt.pcap_Flow

python labeler.py csv\csv enp0s3-pvt-tuesday.pcap_Flow => NO changes
python labeler.py csv\csv enp0s3-public-tuesday.pcap_Flow 184.98.36.245 "16/07/2019 07:00:00 PM" "16/07/2019 07:20:00 PM" "*" => Network Scan, Reconnaissance => 362 records updated
python labeler.py csv\csv enp0s3-public-tuesday.pcap_Flow 184.98.36.245 "16/07/2019 07:28:00 PM" "16/07/2019 07:34:00 PM" "9000" => Web Vulnerability Scan, Reconnaissance => 2411 records updated
python labeler.py csv\csv enp0s3-public-tuesday.pcap_Flow 184.98.36.245 "16/07/2019 07:35:00 PM" "16/07/2019 07:41:00 PM" "9002" => Web Vulnerability Scan, Reconnaissance => 163 records updated
python labeler.py csv\csv enp0s3-public-tuesday.pcap_Flow 184.98.36.245 "16/07/2019 07:42:00 PM" "16/07/2019 07:50:00 PM" "9003" => Web Vulnerability Scan, Reconnaissance => 0 records updated
python labeler.py csv\csv enp0s3-public-tuesday.pcap_Flow 184.98.36.245 "16/07/2019 08:00:00 PM" "16/07/2019 08:20:00 PM" "9002" => Account BruteForce, Reconnaissance => 50 records updated
python labeler.py csv\csv enp0s3-public-tuesday.pcap_Flow 184.98.36.245 "16/07/2019 08:30:00 PM" "16/07/2019 08:50:00 PM" "*" => Network Scan, Reconnaissance => 488 records updated

python labeler.py csv\csv enp0s3-pvt-wednesday.pcap_Flow => NO changes
python labeler.py csv\csv enp0s3-public-wednesday.pcap_Flow 184.98.36.245 "17/07/2019 07:20:00 PM" "17/07/2019 07:25:00 PM" "9002" => Account Bruteforce, Reconnaissance => 44 records updated
python labeler.py csv\csv enp0s3-public-wednesday.pcap_Flow 184.98.36.245 "17/07/2019 07:25:01 PM" "17/07/2019 07:28:00 PM" "9002" => CSRF, Establish Foothold => 7 records updated
python labeler.py csv\csv enp0s3-public-wednesday.pcap_Flow 184.98.36.245 "17/07/2019 07:33:00 PM" "17/07/2019 07:39:00 PM" "9002" => SQL Injection, Establish Foothold => 30 records updated
MANUAL UPDATE => enp0s3-public-wednesday.pcap_Flow 192.168.3.29-206.207.50.50 "17/07/2019 10:03:00 PM" "17/07/2019 10:06:00 PM" => Malware Download, Establish Foothold => 2 records updated

python labeler.py csv\csv enp0s3-pvt-thursday.pcap_Flow => NO changes
python labeler.py csv\csv enp0s3-public-thursday.pcap_Flow 192.168.3.29 "18/07/2019 08:05:00 PM" "18/07/2019 09:01:00 PM" "4444" => Backdoor, Lateral Movement => 20 records updated

MANUAL UPDATE => enp0s3-tcpdump-pvt-friday.pcap_Flow 192.168.3.30-206.207.50.50 "19/07/2019 10:21:00 PM" "19/07/2019 10:22:00 PM" => Data Exfiltration, Data Exfiltration
python labeler.py csv\csv enp0s3-tcpdump-friday.pcap_Flow 184.98.36.245  "19/07/2019 06:44:00 PM" "19/07/2019 06:44:59 PM" "9002" => Command Injection, Establish Foothold => 12 records updated
