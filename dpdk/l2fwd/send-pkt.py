#!/usr/bin/env python3
from scapy.all import Ether, IP, ICMP, send, get_if_hwaddr, GRE

iface = "enX0" # your traffic gen's interface

#pkt = (IP(dst="192.102.1.14")/GRE()/Ether(src=get_if_hwaddr(iface), dst="0e:08:d2:6e:af:05") / IP(dst="192.102.1.65") / ICMP())
pkt = (IP(dst="192.102.1.14")/GRE()/Ether(src="0E:C1:21:B2:85:CB", dst="0e:08:d2:6e:af:05") / IP(dst="192.102.1.65", src="192.102.1.25") / ICMP())
send(pkt, iface=iface, count=10, inter=2, loop=1)
