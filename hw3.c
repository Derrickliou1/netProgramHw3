//gcc -o hw3xxx hw3xxx.c -lpcap
#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>


#include <netinet/in.h>

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
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */

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

struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */

};

#define SIZE_UDP        8               /* length of UDP header */

int count,n,total;

void summary(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;                   /* packet counter */

 
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const struct sniff_udp *udp;


    const char *payload;                    /* Packet payload */
    int i;
    int size_ip;
    int size_tcp;
    int size_payload;
    struct timeval tv;
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[64], buf[64],showbuf[64]="";

    bool tcp_packet = false, udp_packet = false, icmp_packet = false;
    
    total=count;

    tv = header->ts;
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(buf, sizeof buf, "%s", tmbuf);
    sprintf(showbuf,"%s%s\t",showbuf,buf);
	

    ethernet = (struct sniff_ethernet*)(packet);


   
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20)
    {

        return;
    }


	if(ip->ip_p==IPPROTO_TCP)
	{
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20)
			return;
		printf("NO.%03d\n",count);
		printf("   Src IP: %s\n", inet_ntoa(ip->ip_src));
		printf("   Dst IP: %s\n", inet_ntoa(ip->ip_dst));
		printf("   Src port: %d\n", ntohs(tcp->th_sport));
        printf("   Dst port: %d\n", ntohs(tcp->th_dport));
        printf("   Protocal:TCP\n");
		printf("   Packt length:%d\n",header->len);

	}
	else if(ip->ip_p==IPPROTO_UDP)
	{
		printf("NO.%03d\n",count);
		printf("   Src IP: %s\n", inet_ntoa(ip->ip_src));
		printf("   Dst IP: %s\n", inet_ntoa(ip->ip_dst));
		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
        printf("   Src port: %d\n", ntohs(udp->uh_sport));
        printf("   Dst port: %d\n", ntohs(udp->uh_dport));
        printf("   Protocal:UDP\n");
		printf("   Packt length:%d\n",header->len);
		
	}
	printf("   Time:%s\n",showbuf);
	count++;
	return;

}



int main(int argc, char** argv)
{
    pcap_t *handle;
    char error[100];

    struct pcap_pkthdr pack;
    const u_char *packet;
    struct pcap_pkthdr header;
    struct bpf_program filter;

    char file[]="./nb6-startup.pcap";
    char expr[256];
    int i;

    printf("輸入過濾條件:\n");
    gets(expr);

    if((handle=pcap_open_offline(file,error))==NULL)
    {
        printf("%s\n",error);
        return 0;
    }

    if(pcap_compile(handle,&filter,expr,1,0)<0)
    {
        printf("%s\n",pcap_geterr(handle));
        return 0;
    }
    if(pcap_setfilter(handle,&filter)==0)
        pcap_loop( handle, -1, summary, NULL);

    
    return 0;
}
