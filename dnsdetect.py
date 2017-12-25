from scapy.all import *
from netifaces import AF_INET, ifaddresses
import argparse
import netifaces
from datetime import datetime
from collections import deque
packet_list = deque(maxlen = 20)

def matchRdata(cp_pkt,pkt):
    dns = pkt['DNS']
    print 'matching r data'
    for i in range(dns.ancount):
        dnsrr = dns.an[i]
    	print dns.an[i]
        print dnsrr.rrname, dnsrr.rdata
    return True
  
def dns_detect(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSRR) and pkt[DNS].qr == 1: 
        if len(packet_list)>0:
            for cp_pkt in packet_list:
                if cp_pkt[IP].dst == pkt[IP].dst and\
                cp_pkt[IP].sport == pkt[IP].sport and\
                cp_pkt[IP].dport == pkt[IP].dport and\
                cp_pkt[DNS].id == pkt[DNS].id and\
                cp_pkt[DNS].qd.qname == pkt[DNS].qd.qname and \
                cp_pkt[DNSRR].rdata != pkt[DNSRR].rdata and \
                cp_pkt[IP].payload != pkt[IP].payload:
                    print "DNS poisoning attempt detected"
                    print datetime.now().strftime("%Y-%m-%d-%H:%M:%S.%f")
                    print "TXID %s Request URL %s"%( cp_pkt[DNS].id, cp_pkt[DNS].qd.qname.rstrip('.'))
                    print "Answer1 [%s]"%cp_pkt[DNSRR].rdata
                    print "Answer2 [%s]"%pkt[DNSRR].rdata
                    print '\n'
        packet_list.append(pkt)

def chooseInterface(interfaceList):
    chose = ''
    for interface in interfaceList:
        #print interface
        #print ifaddresses(interface)
        if "lo" not in interface:
            for i in ifaddresses(interface).setdefault(AF_INET, [{'addr': 'None'}]):
                if i['addr'] is not 'None':
                    ip = i['addr']
                    chose = interface

    return str(chose)

def argParser():
    parser = argparse.ArgumentParser(add_help = False, description='Process some integers.')
    parser.add_argument("-r", "--file", dest="trace",
                  help="a FILE containing ip addresses and host names to be hijacked", metavar="FILE")
    parser.add_argument("-i",
                  help="specifies interface to listen to", metavar="eth0")
    parser.add_argument('expression', nargs='*', action="store")
    args = parser.parse_args()
    return args.i, args.trace, args.expression

if __name__ == '__main__':
    trace_flag = 0
    interface, trace, expression = argParser()
    if not expression:
    	expression = ''
    if interface:
        interface_flag = 1
    else:
        interface_flag = 0
        interface = chooseInterface(netifaces.interfaces())
        print 'No interface selected sniffing on default interface:'
        print interface
    if trace:
        trace_flag = 1
    else:
        print 'capturing all traffic'
    try:
        if interface_flag == 1 and trace_flag == 1:
            print "Enter one argument only :either the interface or the pcap filename"
            sys.exit()
        elif interface_flag == 0 and trace_flag == 1:
            print "Sniffing from the tracefile"
            sniff(filter=expression, offline=trace, store=0, prn=dns_detect)
        else:
            sniff(filter=expression, iface=interface, store = 0, prn = dns_detect)

    except AttributeError:
        print 'Invalid attributes supplied to dns detect',
        print 'correct format is dnsdetect [-i interface] [-r tracefile] expression'


'''
http://bt3gl.github.io/black-hat-python-infinite-possibilities-with-the-scapy-module.html
http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html#selection-1213.0-1213.1
'''

