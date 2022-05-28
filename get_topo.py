import scapy
from scapy.all import *
from collections import defaultdict

data_path = "./topo/1-ping-PE1-g01.pcap"

l3_links = []
l2_links = []

ip_2_mac_dict = defaultdict(set)


def read_pkt_1():
    for packet in PcapReader(data_path):
        try:

            s = packet.read_packet()
            print(s)
            print(packet)



        except Exception as e:
            print(e)
            pass


def read_sniff():
    pkts = sniff(offline=data_path)
    print(pkts.summary())


def deal_layers(pkt):
    for layer in pkt.layers():
        print(layer.type)
        print(1)

# def deal_IP(pkt):

def get_eth_ip(pkt: scapy.packet.Packet):
    src_mac = dst_mac = src_ip = dst_ip = None
    if pkt.haslayer("Ether"):
        eth = pkt.getlayer("Ether")
        src_mac = eth.src
        dst_mac = eth.dst

    if pkt.haslayer("IP"):
        IP = pkt.getlayer("IP")
        src_ip = IP.src
        dst_ip = IP.dst

    if src_mac is not None and dst_mac is not None:
        l2_link = (src_mac, dst_mac)
        if l2_link not in l2_links:
            l2_links.append(l2_link)

    if src_ip is not None and dst_ip is not None:
        l3_link = (src_ip, dst_ip)
        if l3_link not in l3_links:
            l3_links.append(l3_link)

            ip_2_mac_dict[src_ip].update(src_mac)
            ip_2_mac_dict[dst_ip].update(dst_mac)


def read_pkt(pcap_file):
    for pkt in rdpcap(pcap_file):

        print(pkt.show())
        print(pkt.summary())
        print(pkt.layers())

        # deal_layers(pkt)

        get_eth_ip(pkt)

    return l2_links, l3_links, ip_2_mac_dict



if __name__ == "__main__":
    # a = read_pkt(data_path)
    read_sniff()