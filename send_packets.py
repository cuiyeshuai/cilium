from scapy.all import *
import time

for i in range(3):
    ip=IP(dst="10.96.0.100")
    timestamp_value = int(time.time())+i
    tcp=TCP(sport=1800, dport=80, seq=12345, window=1000,options=[('Timestamp', (timestamp_value, 0))])
    pkt=ip/tcp
    send(pkt)