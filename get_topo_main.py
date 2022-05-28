import os
from collections import defaultdict
from .get_topo import *

data_path = "./pcap/"

def reconstruct(l2s, l3s, ip2macs):
    for ip2mac in ip2macs:




def build_topo(data_path):
    files = [file for file in os.listdir(data_path) if file.endswith(".pcap")]

    l2_links = l3_links = list()
    ip2mac = defaultdict(set)
    for file in files:
        tmp_l2, tmp_l3, tmp_ip2mac = read_pkt(file)
        l2_links.extend(tmp_l2)
        l3_links.extend(tmp_l3)

        for k,v in tmp_ip2mac.items():
            if k in ip2mac.keys():
                ip2mac[k] = v | ip2mac[k]
            else:
                ip2mac[k] = v

    reconstruct(set(l2_links), set(l3_links), ip2mac)


if __name__ == "__main__":
    build_topo(data_path)
