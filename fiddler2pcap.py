#!/usr/bin/python
# This is probably useful to like 4 people. Some of the packet inection stuff is taken from rule2alert https://code.google.com/p/rule2alert/ which is GPLv2 so I guess this is well.
# This ultra alpha if everything isn't right it will fall on its face and probably cause you to run away from it screaming into the night

#TODO:
# 1. Optionally trim request line to start with uripath 
# 2. Better error checking... Well any error checking really.

import random
import os
import sys
import re
from xml.dom.minidom import parse, parseString
from scapy.utils import PcapWriter
from scapy.all import *
import glob
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-i", dest="fiddler_raw_dir", type="string", help="path to fiddler raw directory we will read from glob format")
parser.add_option("-o", dest="output_pcap", type="string", help="path to output PCAP file")
(options, args) = parser.parse_args()
if options == []:
   print parser.print_help()
   sys.exit(-1)
if not options.fiddler_raw_dir or options.fiddler_raw_dir == "":
   print parser.print_help()
   sys.exit(-1)
if not options.output_pcap or options.output_pcap == "":
   print parser.print_help()
   sys.exit(-1)

#Open our packet dumper
pktdump = PcapWriter(options.output_pcap, sync=True)


def build_handshake(src,dst,sport,dport):
    ipsrc   = src
    ipdst   = dst
    portsrc = sport
    portdst = dport

    client_isn = random.randint(1024, (2**32)-1)
    server_isn = random.randint(1024, (2**32)-1)
    syn = IP(src=ipsrc, dst=ipdst)/TCP(flags="S", sport=portsrc, dport=portdst, seq=client_isn)
    synack = IP(src=ipdst, dst=ipsrc)/TCP(flags="SA", sport=portdst, dport=portsrc, seq=server_isn, ack=syn.seq+1)
    ack = IP(src=ipsrc, dst=ipdst)/TCP(flags="A", sport=portsrc, dport=portdst, seq=syn.seq+1, ack=synack.seq+1)
    pktdump.write(syn)
    pktdump.write(synack)
    pktdump.write(ack)
    return(ack.seq,ack.ack)

def build_finshake(src,dst,sport,dport,seq,ack):
    ipsrc   = src
    ipdst   = dst
    portsrc = sport
    portdst = dport
    finAck = IP(src=ipsrc, dst=ipdst)/TCP(flags="FA", sport=sport, dport=dport, seq=seq, ack=ack)
    finalAck = IP(src=ipdst, dst=ipsrc)/TCP(flags="A", sport=dport, dport=sport, seq=finAck.ack, ack=finAck.seq+1)
    pktdump.write(finAck)
    pktdump.write(finalAck)

#http://stackoverflow.com/questions/18854620/whats-the-best-way-to-split-a-string-into-fixed-length-chunks-and-work-with-the
def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def make_poop(src,dst,sport,dport,seq,ack,payload):
    segments = [] 
    if len(payload) > 1460:
        segments=chunkstring(payload,1460)
    else:
        segments.append(payload)    
    ipsrc   = src
    ipdst   = dst
    portsrc = sport
    portdst = dport
    for segment in segments:
        p = IP(src=ipsrc, dst=ipdst)/TCP(flags="PA", sport=sport, dport=dport, seq=seq, ack=ack)/segment
        returnAck = IP(src=ipdst, dst=ipsrc)/TCP(flags="A", sport=dport, dport=sport, seq=p.ack, ack=(p.seq + len(p[Raw])))
        seq = returnAck.ack
        ack = returnAck.seq
        pktdump.write(p)
        pktdump.write(returnAck)
    return(returnAck.seq,returnAck.ack)
    
if os.path.isdir(options.fiddler_raw_dir):
    m_file_list=glob.glob("%s/%s" % (options.fiddler_raw_dir,"*_m.xml")) 
    m_file_list.sort()
    for xml_file in m_file_list:
        src =""
        dst =""
        sport=""
        dport=80
        dom = parse(xml_file)
        m = re.match(r"^(?P<fid>\d+)_m\.xml",os.path.basename(xml_file))
        if m:
            fid = m.group("fid")
        else:
            print("failed to get fiddler id tag")
            sys.exit(-1)
        
        xmlTags = dom.getElementsByTagName('SessionFlag')
        for xmlTag in xmlTags:
            xmlTag = xmlTag.toxml()
            m = re.match(r"\<SessionFlag N=\x22x-(?:client(?:ip\x22 V=\x22[^\x22]*?(?P<clientip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|port\x22 V=\x22(?P<sport>\d+))|hostip\x22 V=\x22[^\x22]*?(?P<hostip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\x22",xmlTag)
            if m and m.group("sport"):
                sport = int(m.group("sport"))
                #sport = random.randint(1024, 65535)
            elif m and m.group("clientip"):
                src = m.group("clientip")
            elif m and m.group("hostip"):
                dst = m.group("hostip")
        req = open(options.fiddler_raw_dir + fid + "_c.txt").read()
        m=re.match(r"^[^\r\n]+?\s+?https?\:\/\/[^\/\r\n]+?\:(?P<dport>\d{1,5})\/",req)
        if m and m.group("dport") and int(m.group("dport")) <= 65535:
            dport = int(m.group("dport"))
        resp = open(options.fiddler_raw_dir + fid + "_s.txt").read()
        print "src: %s dst: %s sport: %s dport: %s" % (src, dst, sport, dport)
        (seq,ack)=build_handshake(src,dst,sport,dport)
        (seq,ack)=make_poop(src,dst,sport,dport,seq,ack,req)
        (seq,ack)=make_poop(dst,src,dport,sport,seq,ack,resp)
        build_finshake(src,dst,sport,dport,seq,ack)

else:
    print "fiddler raw dir specified:%s dos not exist" % (options.fiddler_raw_dir)
    sys.exit(-1)

pktdump.close()
