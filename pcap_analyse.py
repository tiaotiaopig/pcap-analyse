from typing import List, Set, Tuple
import scapy.all as sca
import dpkt
import os

'''
sniff(count=0,
      store=1,
      offline=None,
      prn=None,
      filter=None,
      L2socket=None,
      timeout=None,
      opened_socket=None,
      stop_filter=None,
      iface=None)

      count:抓取报的数量，设置为0时则一直捕获
store:保存抓取的数据包或者丢弃，1保存，0丢弃
offline:从pcap文件中读取数据包，而不进行嗅探，默认为None
prn:为每个数据包定义一个回调函数
filter:过滤规则，可以在里面定义winreshark里面的过滤语法
L2socket:使用给定的L2socket
timeout:在给定的事件后停止嗅探，默认为None
opened_socket:对指定的对象使用.recv进行读取
stop_filter:定义一个函数，决定在抓到指定的数据之后停止
iface:指定抓包的网卡,不指定则代表所有网卡

Ether:src, dst, type
IP:proto, src, dst
'''

base_dir = os.path.dirname(os.path.realpath(__file__))
    
def pkt_handler(file_path: str, protocols: Set[str]={'ah', 'tcp', 'udp'}) -> Set[Tuple[str, str]]:
    '''
        从一个.pcap文件中获取所有mac层链路
        忽略了广播的流量
    '''
    mac_links = set()
    packet_list = sca.rdpcap(file_path)
    pkt = packet_list[18]
    cdp = pkt.getlayer('Raw')
    for pkt in packet_list[18]:
        if not pkt.haslayer('Ether') or not pkt.haslayer('IP'): continue
        ip = pkt.getlayer('IP')
        proto = ip.get_field('proto').i2s[ip.proto]
        # 只使用IPsec的pcap
        # if proto not in protocols: continue
        eth = pkt.getlayer("Ether")
        src_mac = eth.src
        dst_mac = eth.dst
        # 忽略广播流量
        if dst_mac == 'ff:ff:ff:ff:ff:ff': continue
        # 无序性
        link = (src_mac, dst_mac) if src_mac < dst_mac else (dst_mac, src_mac)
        mac_links.add(link)
    return mac_links

def link_merge(link_set: Set[Tuple[str, str]]) -> Set[Tuple[str, str]]:
    '''
        link_set是所有pcap文件解析出的链路集合
    '''
    mac_set = set()
    for src, dst in link_set:
        mac_set.add(src)
        mac_set.add(dst)
    # mac地址前五个字节相同,认为是一个节点
    sort_list = sorted(mac_set)
    start_id, id_list = -1, []
    pre = ''
    for mac in sort_list:
        if pre[0: pre.rfind(':')] != mac[0: mac.rfind(':')]: start_id += 1
        id_list.append(start_id)
        pre = mac
    # mac -> id 的映射
    mac2id = {sort_list[index]: id_list[index] for index in range(len(sort_list))}
    # 开始合并
    merged_links = set()
    for src_mac, dst_mac in link_set:
        merged_links.add((mac2id[src_mac], mac2id[dst_mac]))
    return merged_links

def topo_from_flow(flows_dir: str) -> List[Tuple[str, str]]:
    '''
        将指定目录中.pcap文件解析为mac拓扑
    '''
    # 1.逐个文件解析,并将解析出的所有mac链路汇总
    links_set = set()
    root_dir = os.path.join(base_dir, flows_dir)
    flow_paths = os.listdir(root_dir)
    for flow_path in flow_paths:
        file_path = os.path.join(root_dir, flow_path)
        links_set = links_set.union(pkt_handler(file_path))
    # 2.将可能是同一节点的链路进行合并
    return link_merge(links_set)


def sniff_filter(file_path: str) -> sca.PacketList:
    filter_str = 'tcp'
    return sca.sniff(offline=file_path, filter=filter_str)
            
if __name__ == '__main__':
    links = topo_from_flow('topo')
    links = sorted(links)
    print(links)