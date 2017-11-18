#include<stdio.h>
#include<stdbool.h>
#include<pcap.h>
#include<time.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<ctype.h>
#include<netinet/in.h>
#include<netinet/ip_icmp.h>
#include<net/if_arp.h>
#include<arpa/inet.h>
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
#define	ETHERTYPE_PUP		0x0200      /* Xerox PUP */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */
char * payload_filter  = NULL;


	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	struct udp_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};
	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}
void printPacketDetails(const struct pcap_pkthdr* pkthdr,const u_char* packet);
/*
 * print packet
 data (avoid printing binary data)
 */
 bool custom_strstr(const u_char* payload, int len, char* payload_filter){
    const u_char *ch;
    ch = payload;
    char * filter;
    filter = payload_filter;
    int i = 0;
    while (i < len) {
		if (isprint(*ch)){
                //printf("%c",*ch);
            while(*ch == *filter){
                filter++;
                ch++;
                i++;
                if(i>len)
                    break;
                if((*filter) == 0){
                        return true;
                }
            }
            filter = payload_filter;
		}
		ch++;
		i++;
	}
	return false;
 }

void print_payload(const u_char *payload, int len,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */

    if(payload_filter != NULL){
        bool ptr = custom_strstr(payload, len, payload_filter);

        if(ptr == false)  // it means the -s expression is not there in payload
            return; // return without printing
    }

    printPacketDetails(pkthdr,packet);
	if (len <= 0)
		return;

    const u_char *ch = payload;
    printf("payload length:%d bytes\n",len);
    //const u_char *ch = &buffer;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}


void printPacketDetails(const struct pcap_pkthdr* pkthdr,const u_char* packet){

    static int count = 1;
    struct sniff_ethernet * ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp* tcp;
    const struct icmphdr* icmp;
    struct udp_hdr *udp;
    u_int size_ip;

     printf("\nPacket number %d:\n", count);
     count++;

     char tmbuf[64],buf[64];
     struct timeval tv;
     time_t nowtime;
     struct tm *nowtm;

     tv= pkthdr->ts;
     nowtime = tv.tv_sec;
     nowtm = localtime(&nowtime);
     strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
     snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, tv.tv_usec);
     printf("%s", buf);

     ethernet = (struct sniff_ethernet*)(packet);
     u_char *ptr;


    ptr = ethernet->ether_shost;
    int i = ETHER_ADDR_LEN;

    do{
        printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("->");


    ptr = ethernet->ether_dhost;
    i = ETHER_ADDR_LEN;
    do{
        printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf(" ");


    printf(" Type 0x0%x", ntohs(ethernet->ether_type));
    printf(" len %d\n",pkthdr->len);

    if (ntohs (ethernet->ether_type) == ETHERTYPE_IP)
    {

        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
        }
        // ip switch

        bool hasport = false;

        switch(ip->ip_p) {
            case IPPROTO_TCP:
                tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
                int size_tcp = TH_OFF(tcp)*4;
                if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
                }

                printf("%s:%d ->", inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));
                printf(" %s:%d", inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport));

                 printf(" TCP\n");
                 hasport = true;
                break;
           case IPPROTO_UDP:
                udp = (struct udp_hdr*)(packet + SIZE_ETHERNET + size_ip);

                printf("%s:%d ->", inet_ntoa(ip->ip_src),ntohs(udp->uh_sport));
                printf(" %s:%d", inet_ntoa(ip->ip_dst),ntohs(udp->uh_dport));

                printf(" UDP\n");
                hasport = true;
                u_int size_udp;
                size_udp = 8;  // header size of udp packet is 8 bytes
                break;
           case IPPROTO_ICMP:
                icmp = (struct icmphdr*)(packet + SIZE_ETHERNET + size_ip);
                printf("%s ->", inet_ntoa(ip->ip_src));
                printf(" %s", inet_ntoa(ip->ip_dst));


                printf(" ICMP\n");
                hasport = true;
                break;
                case IPPROTO_IP:
                printf(" IP\n");
                break;
                default:
                printf(" unknown\n");
                break;
	        }
	            if(hasport == false){
                   // print source and destination IP addresses
                printf("       From: %s\n", inet_ntoa(ip->ip_src));
                printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	            }

   }
   else  if (ntohs (ethernet->ether_type) == ETHERTYPE_ARP)
    {
         printf("\n ARP Packet\n");
    }else {
         printf("\n Not an IP Packet\n");
      }
}


void got_packet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet){

    struct sniff_ethernet * ethernet;
    const struct sniff_ip *ip; /* The IP header */
    struct udp_hdr *udp;
    const struct sniff_tcp *tcp;
    u_int size_tcp;
    u_int size_ip;

	ethernet = (struct sniff_ethernet*)(packet);
	u_char *ptr;

    ptr = ethernet->ether_dhost;
    int i = ETHER_ADDR_LEN;

    const u_char *payload; /* Packet payload */
    int size_payload;

    if (ntohs (ethernet->ether_type) == ETHERTYPE_IP)
    {
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
		return;
        }

        /* determine protocol */
        bool hasport = false;

        switch(ip->ip_p) {
            case IPPROTO_TCP:
                tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
                size_tcp = TH_OFF(tcp)*4;
                if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
                }

                /* define/compute tcp payload (segment) offset */
                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

                /* compute tcp payload (segment) size */
                size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

                    /*
                     * Print payload data; it might be binary, so don't just
                     * treat it as a string.
                     */
                    if (size_payload > 0) {
                        print_payload(payload, size_payload,pkthdr,packet);
                    }else if (payload_filter == NULL){
                        // call the function print packet details
                        printPacketDetails(pkthdr,packet);
                    }

                break;
            case IPPROTO_UDP:
                udp = (struct udp_hdr*)(packet + SIZE_ETHERNET + size_ip);
                u_int size_udp;

                size_udp = 8;  // header size of udp packet is 8 bytes
                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
             	size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
                if (size_payload > 0) {
		         print_payload(payload, size_payload,pkthdr,packet);
	             }
	             else if (payload_filter == NULL){
                        // call the function print packet details
                        printPacketDetails(pkthdr,packet);
                    }
                break;
             case IPPROTO_ICMP:
                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);
             	size_payload = ntohs(ip->ip_len) - (size_ip + 8);
                if (size_payload > 0) {
		         print_payload(payload, size_payload,pkthdr,packet);
	             }
	             else if (payload_filter == NULL){
                        // call the function print packet details
                        printPacketDetails(pkthdr,packet);
                    }
                break;
                case IPPROTO_IP:
                printf("   Protocol: IP\n");
                break;
                default:
                break;
	        }

    }else  if (ntohs (ethernet->ether_type) == ETHERTYPE_ARP)
    {
                payload = (u_char *)(packet + SIZE_ETHERNET);
             	size_payload = (pkthdr->len) - (SIZE_ETHERNET);
                if (size_payload > 0) {

		         print_payload(payload, size_payload,pkthdr,packet);
                }else if (payload_filter == NULL){
                        // call the function print packet details
                        printPacketDetails(pkthdr,packet);
                    }
    }else {
        payload = (u_char *)(packet + SIZE_ETHERNET);
        size_payload = ntohs(pkthdr->len) - (SIZE_ETHERNET);
                if (size_payload > 0) {

		         print_payload(payload, size_payload,pkthdr,packet);
                }
                else if (payload_filter == NULL){
                       printPacketDetails(pkthdr,packet);
                    }
      }
}
int main(int argc, char ** argv){

extern char *optarg;
extern int optind;
char* filter_exp =  NULL;
int c, err = 0;
int deviceflag =0, readfile = 0, filterflag =0;
char * dev, *filename;
char errbuf[PCAP_ERRBUF_SIZE];
while ((c = getopt(argc, argv, "i:r:s:")) != -1){
		switch (c) {
		case 'i':
			deviceflag = 1;
			dev = optarg;
			break;
		case 'r':
			readfile = 1;
			filename = optarg;
			break;
		case 's':
			// pflag = 1;
			filterflag = 1;
			payload_filter = optarg;
			break;
		case '?':
			err = 1;
			break;
		}
    }
if(err ==1 ){
  fprintf(stderr, "nonsense argument %s\n", errbuf);
			return(2);
}

if(deviceflag == 0){
   dev = pcap_lookupdev(errbuf);

		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
}

printf("Device: %s\n", dev);
pcap_t *handle;

if(readfile){
   handle = pcap_open_offline(filename,errbuf);
}
else{
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		 return(2);
	 }
}

if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
	}
     filter_exp = argv[optind];
     fflush(stdout);

     struct bpf_program fp;		/* The compiled filter expression */
	 bpf_u_int32 mask;		/* The netmask of our sniffing device */
	 bpf_u_int32 net;		/* The IP of our sniffing device */

	 if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		 fprintf(stderr, "Can't get netmask for device %s\n", dev);
		 net = 0;
		 mask = 0;
	    }

	    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	     }
	     if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	     }

         pcap_loop(handle,-1, got_packet, NULL);  // handle is the session, -1 means continuous sniffing
         pcap_close(handle);
		return(0);
}

