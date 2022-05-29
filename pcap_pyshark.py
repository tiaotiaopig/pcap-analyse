from typing import List, Set, Tuple
import pyshark
import os


class NodeInfo():
    def __init__(self, device_id:str='') -> None:
        '''
            主要封装解析出的cdp信息
        '''
        self.device_id = device_id
        self.port_id = []
        self.ips = []
        self.macs = []
        self.software_version = ''
        self.platform = ''

base_dir = os.path.dirname(os.path.realpath(__file__))

'''
cdp_layer::field_names，可以通过get(item:str)获取

['version', 'ttl', 'checksum', 'checksum_status', '', 'tlv_type',
'tlv_len', 'deviceid', 'software_version', 'platform', 
'number_of_addresses', 'protocol_type', 'protocol_length',
'protocol', 'address_length', 'nrgyz_ip_address', 'portid',
'capabilities', 'capabilities_router', 'capabilities_trans_bridge',
'capabilities_src_bridge', 'capabilities_switch', 'capabilities_host',
'capabilities_igmp_capable', 'capabilities_repeater',
'capabilities_voip_phone', 'capabilities_remote',
'capabilities_cvta', 'capabilities_mac_relay',
'vtp_management_domain', 'duplex']
'''

def pcap_parse(pcap_path:str, filter:str='cdp') -> Set[NodeInfo]:
    '''
        解析单个pcap包，默认是在一个端口采集的
        那么根据源mac就可以解析出有多少条链路
    '''
    node_set = set()
    pkts = pyshark.FileCapture(pcap_path, display_filter=filter)
    for pkt in pkts:
        # eth_layer = pkt.eth
        cdp_layer = pkt.cdp
        # print(cdp_layer.field_names)
        # 这种直接调用的方式也行
        # device_id = pkt.cdp.deviceid
        device_id = cdp_layer.get('deviceid')
        node = NodeInfo(device_id)
        node.port_id.append(cdp_layer.get('portid'))
        node.ips.append(cdp_layer.get('nrgyz_ip_address'))
        node.software_version = cdp_layer.get('software_version')
        node.platform = cdp_layer.get('platform')
        node.macs.append(pkt.eth.src_resolved)
        node_set.add(node)
    return node_set


def topo_from_flow(flows_dir: str) -> None:
    '''
        将指定目录中.pcap文件解析为NodeInfo集合
    '''
    # 1.逐个文件解析,并将解析出的所有mac链路汇总
    links_set = set()
    root_dir = os.path.join(base_dir, flows_dir)
    flow_paths = os.listdir(root_dir)
    for flow_path in flow_paths:
        pcap_path = os.path.join(root_dir, flow_path)
        links_set = links_set.union(pcap_parse(pcap_path))
    return links_set


if __name__ == '__main__':
    topo_from_flow('topo')