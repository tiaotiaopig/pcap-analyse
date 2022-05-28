>> cdp_p = cdp_pkts[1]

>>> cdp_p

<Dot3  dst=01:00:0c:cc:cc:cc src=00:19:06:ea:b8:85 len=386 |<LLC  dsap=0xaa ssap=0xaa ctrl=3 |<SNAP  OUI=0xc code=0x2000 

|<CDPv2_HDR  vers=2 ttl=180 cksum=0xb0bd msg=[<CDPMsgDeviceID  type=Device ID len=10 val='Switch' |>, <CDPMsgSoftwareVersion 

type=Software Version len=196 val='Cisco IOS Software, C3560 Software (C3560-ADVIPSERVICESK9-M), Version 12.2(25)SEB4, RELEASE

 SOFTWARE (fc1)\nCopyright (c) 1986-2005 by Cisco Systems, Inc.\nCompiled Tue 30-Aug-05 17:56 by yenanh' |>, <CDPMsgPlatform  

type=Platform len=24 val='cisco WS-C3560G-24PS' |>, <CDPMsgAddr  type=Addresses len=17 naddr=1 addr=[<CDPAddrRecordIPv4  

ptype=NLPID plen=1 proto='\xcc' addrlen=4 addr=192.168.0.1 |>] |>, <CDPMsgPortID  type=Port ID len=22 iface='GigabitEthernet0/5' 

|>, <CDPMsgCapabilities  type=Capabilities len=8 cap=Switch+IGMPCapable |>, <CDPMsgProtoHello  type=Protocol Hello len=36 

val='\x00\x00\x0c\x01\x12\x00\x00\x00\x00\xff\xff\xff\xff\x01\x02!\xff\x00\x00\x00\x00\x00\x00\x00\x19\x06\xea\xb8\x80\xff\x00\x00' 

|>, <CDPMsgVTPMgmtDomain  type=VTP Mangement Domain len=7 val='Lab' |>, <CDPMsgNativeVLAN  type=Native VLAN len=6 vlan=1 |>,

<CDPMsgDuplex  type=Duplex len=5 duplex=Full |>, <CDPMsgGeneric  type=Trust Bitmap len=5 val='\x00' |>, <CDPMsgGeneric  

type=Untrusted Port CoS len=5 val='\x00' |>, <CDPMsgMgmtAddr  type=Management Address len=17 naddr=1 addr=[<CDPAddrRecordIPv4  

ptype=NLPID plen=1 proto='\xcc' addrlen=4 addr=192.168.0.1 |>] |>, <CDPMsgGeneric  type=Power Available 

len=16 val='\x00\x00\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff' |>] |>>>>

>>>


dst        : DestMACField         = '01:00:0c:cc:cc:cc' (None)

src        : MACField             = '00:19:06:ea:b8:85' ('00:00:00:00:00:00')

len        : LenField             = 386             (None)

--

dsap       : XByteField           = 170             (0)

ssap       : XByteField           = 170             (0)

ctrl       : ByteField            = 3               (0)

--

OUI        : X3BytesField         = 12              (0)

code       : XShortEnumField      = 8192            (0)

--

vers       : ByteField            = 2               (2)

ttl        : ByteField            = 180             (180)

cksum      : XShortField          = 45245           (None)

msg        : PacketListField      = [<CDPMsgDeviceID  type=Device ID len=10 val='Switch' |>, 

<CDPMsgSoftwareVersion  type=Software Version len=196 val='Cisco IOS Software, C3560 Software 

(C3560-ADVIPSERVICESK9-M), Version 12.2(25)SEB4, RELEASE SOFTWARE (fc1)\nCopyright (c) 1986-2005 

by Cisco Systems, Inc.\nCompiled Tue 30-Aug-05 17:56 by yenanh' |>, <CDPMsgPlatform  type=Platform l

en=24 val='cisco WS-C3560G-24PS' |>, <CDPMsgAddr  type=Addresses len=17 naddr=1 addr=[<CDPAddrRecordIPv4  

ptype=NLPID plen=1 proto='\xcc' addrlen=4 addr=192.168.0.1 |>] |>, <CDPMsgPortID  type=Port ID len=22 

iface='GigabitEthernet0/5' |>, <CDPMsgCapabilities  type=Capabilities len=8 cap=Switch+IGMPCapable 

|>, <CDPMsgProtoHello  type=Protocol Hello len=36 val='\x00\x00\x0c\x01\x12\x00\x00\x00\x00\xff\xff\xff\xff\x01\x02!\xff\x00\x00\x00\x00\x00\x00\x00\x19\x06\xea\xb8\x80\xff\x00\x00' |>, <CDPMsgVTPMgmtDomain  type=VTP Mangement Domain len=7 val='Lab' |>, <CDPMsgNativeVLAN  type=Native VLAN len=6 vlan=1 |>, <CDPMsgDuplex  type=Duplex len=5 duplex=Full |>, <CDPMsgGeneric  type=Trust Bitmap len=5 val='\x00' |>, <CDPMsgGeneric  type=Untrusted Port CoS len=5 val='\x00' |>, <CDPMsgMgmtAddr  type=Management Address len=17 naddr=1 addr=[<CDPAddrRecordIPv4  ptype=NLPID plen=1 proto='\xcc' addrlen=4 addr=192.168.0.1 |>] |>, <CDPMsgGeneric  type=Power Available len=16 val='\x00\x00\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff' |>] ([])

 def process_packets(pkts):

  2:     """

  3:     Function for processing packets and printing information of CDP Packets

  4:     """

  5: 

  6:     for p in pkts:

  7:         # Check if the packet is a CDP Packet

  8:         if Dot3 in p and p.dst == '01:00:0c:cc:cc:cc':

  9:            

 10:             print "\n*******************************"

 11:             

 12:             print "Source MAC:", p.src

 13:             # Process each field in the packet message

 14:             for f in p[CDPv2_HDR].fields["msg"]:

 15: 

 16:                 # Check if the filed type is a known one

 17:                 if f.type in _cdp_tlv_types:

 18: 

 19:                     # Process each field according to type

 20:                     f_type = _cdp_tlv_types[f.type]

 21: 

 22:                     # Make sure we process each address in the message

 23:                     if re.match(r"(Addresses|Management Address)", f_type):

 24:                         for ip in f.fields["addr"]:

 25:                             print f_type, ip.addr

 26: 

 27:                     elif f_type == "Software Version":

 28:                         print f_type+":"

 29:                         print "\t" + string.replace(f.val, "\n", "\n\t")

 30: 

 31:                     elif f_type == "Port ID":

 32:                         print f_type, ":", f.iface

 33: 

 34:                     elif f_type == "Capabilities":

 35:                         # Ugly but works :)

 36:                         print f_type, ":", "".join(re.findall(r"cap\s*=(\S*)", str(f.show)))

 37: 

 38:                     elif re.match(r"Native VLAN|VoIP VLAN Reply",f_type):

 39:                         print f_type, ":", f.vlan

 40: 

 41:                     elif f_type == "Duplex":

 42:                         print f_type, ":", _cdp_duplex[f.duplex]

 43: 

 44:                     elif f_type == "IP Prefix":

 45:                         print f_type, ":", f.defaultgw

 46: 

 47:                     elif f_type == "Power":

 48:                         print f_type, ":", f.power, " mW"

 49: 

 50:                     # Fields not yet implemented in the current version of the

 51:                     # contributed cdp module.

 52:                     elif f_type == "Power Available":

 53:                         # I know, this should provide the amount of power

 54:                         print f_type, ": POE Enabled"

 55: 

 56:                     elif f_type == "Protocol Hello":

 57:                         pass

 58: 

 59:                     else:

 60:                         try:

 61:                             # Make sure we do not have an empty value and print

 62:                             if f.val is not '\0' and len(f.val) != 0: print f_type, ":", f.val

 63: 

 64:                         except Exception, e:

 65:                             print "ERROR!!!!:", f_type

 66:                             print e

 67:                             print "Send error to: carlos_perez[at]darkoperator.com"

 68:                             pass
