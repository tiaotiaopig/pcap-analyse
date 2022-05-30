from typing import List, Set, Tuple
import pyshark
import os

class PortInfo():
    
    def __init__(self, mac:str, ip) -> None:
        self.mac = mac
        self.ip = ip
        self.device_id = ''
        self.port_id = ''
        self.software_version = ''
        self.platform = ''
        
    def __hash__(self) -> int:
        return hash(self.mac)
    
    def __eq__(self, o: object) -> bool:
        return self.mac == o.mac if isinstance(o, PortInfo) else False

class NodeInfo():
    def __init__(self, device_id:str='') -> None:
        '''
            主要封装解析出的cdp信息
            device_id不能作为键,有重复的
            增加工作量,真的好气
        '''
        # 一台设备拥有若干端口,每个端口拥有一个ip和mac
        self.node_id = -1
        self.ports = []
        self.device_id = device_id

# 项目根路径
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

def pcap_parse(pcap_path:str, filter:str='cdp') -> Tuple[PortInfo]:
    '''
        解析单个pcap包，默认是在一个端口采集的
        那么一个端口只存在一条链路,所以返回结果就是节点对
    '''
    port_list, src_mac_set = set(), set()
    pkts = pyshark.FileCapture(pcap_path, display_filter=filter)
    for pkt in pkts:
        # eth_layer = pkt.eth
        cdp_layer = pkt.cdp
        # print(cdp_layer.field_names)
        # 这种直接调用的方式也行
        # device_id = pkt.cdp.deviceid
        # deviceid存在重复,只能使用src_mac作为去重指标了
        src_mac = pkt.eth.src_resolved
        if src_mac in src_mac_set: continue
        src_mac_set.add(src_mac)
        
        port = PortInfo(src_mac, cdp_layer.get('nrgyz_ip_address'))
        port.port_id = cdp_layer.get('portid')
        port.device_id = cdp_layer.get('deviceid')
        port.software_version = cdp_layer.get('software_version')
        port.platform = cdp_layer.get('platform')
        
        port_list.add(port)
    pkts.close()
    # 排序是为了后续边去重,我们需要的是无向边
    return tuple(sorted(port_list, key=lambda port: port.mac))


def topo_from_flow(flows_dir: str):
    '''
        将指定目录中.pcap文件解析为NodeInfo集合
    '''
    # 1.逐个文件解析,并将解析出的所有mac链路汇总
    links_set = set()
    root_dir = os.path.join(base_dir, flows_dir)
    flow_paths = os.listdir(root_dir)
    for flow_path in flow_paths:
        pcap_path = os.path.join(root_dir, flow_path)
        # 出现在一个pcap文件中的port,认为是一条链路
        # 用src_mac作为端口的键
        # 理论上port_tuple只有两个元素, 可以直接作为边
        port_tuple = pcap_parse(pcap_path)
        links_set.add(port_tuple)
    # 再从所有链路集合中找出所有设备节点
    # 使用端口上的deviceid作为端口合并的依据
    deviceid_node_map = {}
    src_device, dst_device = None, None
    for src_port, dst_port in links_set:
        src_device = src_port.device_id
        if src_device not in deviceid_node_map:
            deviceid_node_map[src_device] = NodeInfo(src_device)
        deviceid_node_map[src_device].ports.append(src_port)
        
        dst_device = dst_port.device_id
        if dst_device not in deviceid_node_map:
            deviceid_node_map[dst_device] = NodeInfo(dst_device)
        deviceid_node_map[dst_device].ports.append(dst_port)
    return links_set, deviceid_node_map

def node_and_link(flows_dir:str):
    '''
        将端口的连接关系转化为设备节点的连接关系(编号关系)
    '''
    links_set, device_node_map = topo_from_flow(flows_dir)
    # 给所有节点编号,不知道后续能不能用到
    for index, item in enumerate(device_node_map.items()): item[1].node_id = index
    # 利用device_id进行端口的合并
    links = [(src.device_id, dst.device_id) for src, dst in links_set]
    for src_id, dst_id in links: print(f'{src_id} -> {dst_id}')
    

if __name__ == '__main__':
    node_and_link('topo')