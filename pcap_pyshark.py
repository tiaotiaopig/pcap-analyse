import pyshark

pcaps = pyshark.FileCapture('topo/1-ping-PE1-g01.pcap')
for pcap in pcaps:
    print(pcap)