#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <cstdio>
#include <iostream>
#include <fstream>
//



using namespace std;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

	FILE* urlfile[17];

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

	 int main(int argc, char *argv[])  
	 {
	int num_packets = 5000;	

	urlfile[0] = fopen("data/par/IP/ip_vhl.txt", "a+"); 
	urlfile[1] = fopen("data/par/IP/ip_tos.txt", "a+");
	urlfile[2] = fopen("data/par/IP/ip_len.txt", "a+");
	urlfile[3] = fopen("data/par/IP/ip_id.txt", "a+");
	urlfile[4] = fopen("data/par/IP/ip_off.txt", "a+");
	urlfile[5] = fopen("data/par/IP/ip_ttl.txt", "a+");
	urlfile[6] = fopen("data/par/IP/ip_p.txt", "a+");
	urlfile[7] = fopen("data/par/IP/ip_sum.txt", "a+");
	urlfile[8] = fopen("data/par/IP/ip_src.txt", "a+");
	urlfile[9] = fopen("data/par/IP/ip_dst.txt", "a+");

	urlfile[10] = fopen("data/par/TCP/th_sport.txt", "a+");
	urlfile[11] = fopen("data/par/TCP/th_dport.txt", "a+");
	urlfile[12] = fopen("data/par/TCP/th_seq.txt", "a+");
	urlfile[13] = fopen("data/par/TCP/th_ack.txt", "a+");
	urlfile[14] = fopen("data/par/TCP/th_offx2.txt", "a+");
	urlfile[15] = fopen("data/par/TCP/th_win.txt", "a+");
	urlfile[16] = fopen("data/par/TCP/th_sum.txt", "a+");
	urlfile[17] = fopen("data/par/TCP/th_urp.txt", "a+");	
			
		pcap_t *handle;			/* Session handle */
		char *dev=NULL;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		
		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);  
		}
		
	
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}

		/* make sure we're capturing on an Ethernet device [2] */
		if (pcap_datalink(handle) != DLT_EN10MB) 
		{
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
		}

	/* Grab a packet */
		pcap_loop(handle, num_packets, got_packet, NULL);
		/* And close the session */

				
		pcap_close(handle);
		
		//fflush(urlfile[0]); //vot


		for(int i=0; i<18; i++)
		{
			fclose(urlfile[i]);
		}

		printf("\ncapturing...\n");
		return(0);
	 }

	void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
	{

        static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	int size_ip;
	int size_tcp;
	
        printf("\nPacket number %d:", count);
        count++;

/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
/*
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
*/
	
	fprintf(urlfile[0],"%d\n", ip->ip_vhl);
	fprintf(urlfile[1],"%d\n", ip->ip_tos);
	fprintf(urlfile[2],"%d\n", ip->ip_len);	
	fprintf(urlfile[3],"%d\n", ip->ip_id);	
	fprintf(urlfile[4],"%d\n", ip->ip_off);
	fprintf(urlfile[5],"%d\n", ip->ip_ttl);
	fprintf(urlfile[6],"%d\n", ip->ip_p);
	fprintf(urlfile[7],"%d\n", ip->ip_sum);
	fprintf(urlfile[8],"%s\n", inet_ntoa(ip->ip_src));
	fprintf(urlfile[9],"%s\n", inet_ntoa(ip->ip_dst));

	
	/* determine protocol */	
/*	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
*/	
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
/*
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
*/	
	fprintf(urlfile[10],"%d\n", tcp->th_sport);
	fprintf(urlfile[11],"%d\n", tcp->th_dport);
	fprintf(urlfile[12],"%d\n", tcp->th_seq);
	fprintf(urlfile[13],"%d\n", tcp->th_ack);
	fprintf(urlfile[14],"%d\n", tcp->th_offx2);
	fprintf(urlfile[15],"%d\n", tcp->th_win);
	fprintf(urlfile[16],"%d\n", tcp->th_sum);
	fprintf(urlfile[17],"%d\n", tcp->th_urp);
	


return;
}




