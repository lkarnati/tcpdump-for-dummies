#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518


int sflag = 0;

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

struct sniff_udp{ //UDP header
    uint16_t udp_src;
    uint16_t udp_dst;
    uint16_t udp_len;
    uint16_t udp_chk;
    
};

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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);


void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		
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

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

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

void print_dMAC_address(struct sniff_ethernet *ethernet){
	int i;
	for(i = 0; i<=4 ; i++){
	printf("%02x:",ethernet -> ether_dhost[i]);
	}
	printf("%02x",ethernet ->ether_dhost[5]);
}

void print_sMAC_address(struct sniff_ethernet *ethernet){

	for(int i = 0; i<=4 ; i++){
	printf("%02x:",ethernet -> ether_shost[i]);
	}
	printf("%02x",ethernet ->ether_shost[5]);
}

void print_ethertype(struct sniff_ethernet *ethernet){
	printf("type 0x%x", ntohs(ethernet ->ether_type));
}

void print_length(struct pcap_pkthdr *header){
	int length = header ->len;
	printf("len %d",length);
}


void print_date_time(struct pcap_pkthdr *header){
	struct timeval tv;
	tv = header ->ts;
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];


nowtime = tv.tv_sec;
nowtm = localtime(&nowtime);
strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
snprintf(buf, sizeof buf, "%s.%06d", tmbuf, tv.tv_usec);
printf("\n%s",buf);
}
/*
 * dissect/print packet
 */

const char *sname;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;

	char *string_check;

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;
	
	ethernet = (struct sniff_ethernet*)(packet);
	
	const char *payload;
	if(ntohs(ethernet ->ether_type) != 0x800){

		payload = (char *)(packet + SIZE_ETHERNET);
		size_payload = header->len - SIZE_ETHERNET;
		if(sflag == 1)
		{
			if(size_payload > 0)
			{
				char *ret;
				ret = strstr(payload, sname);
				if(ret)
				{
					print_date_time(header);
					printf(" ");
					print_sMAC_address(ethernet);
					printf(" -> ");
					print_dMAC_address(ethernet);
					printf(" ");
					print_ethertype(ethernet);
					printf(" ");
					print_length(header);
					printf("\n");

					print_payload(payload, size_payload);

				}
			}
		}
		else
		{
			print_date_time(header);
			printf(" ");
			print_sMAC_address(ethernet);
			printf(" -> ");
			print_dMAC_address(ethernet);
			printf(" ");
			print_ethertype(ethernet);
			printf(" ");
			print_length(header);
			printf("\n");

			if(size_payload > 0)
			{
				print_payload(payload, size_payload);
			}

		}


	}
	else
		{
			/* define/compute ip header offset */
			ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
			size_ip = IP_HL(ip)*4;

			if (size_ip < 20) {
				printf("   * Invalid IP header length: %u bytes\n", size_ip);
				return;
			}

			char *ch;
			
			//char ascii_payload[size_payload];
			int x;

				switch(ip->ip_p) {
					case IPPROTO_TCP:{
						tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
						size_tcp = TH_OFF(tcp)*4;
						if (size_tcp < 20) 
							{
								printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
								//return;
							}

						payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
						size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
   						
						//char *ch;
						ch = payload;
						char ascii_payload[size_payload];
						//int x;
						int y = 0;
						for(x = 0; x < size_payload;x++){
							if(isprint(*ch)){
								ascii_payload[y++] = *ch;
							}
							ch++;
						}
						
						if (sflag == 1) 
						{
							if(size_payload > 0)
							{
								char *ret;
								ret = strstr(ascii_payload, sname);
								//printf("ret = %s\n", ret);
								if(ret)
								{
									//printf("Matched ret\n");
									print_date_time(header);
									printf(" ");
									print_sMAC_address(ethernet);
									printf(" -> ");
									print_dMAC_address(ethernet);
									printf(" ");
									print_ethertype(ethernet);
									printf(" ");
									print_length(header);
									printf("\n");
									
									printf("%s:%d", inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));
									printf(" -> ");
									printf("%s:%d", inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport));
									printf(" ");
									printf("TCP \n");
									
									//printf("\n SIZE OF TCP %d",size_tcp);
									print_payload(payload, size_payload);
						  		}
							}
							
						}
						else
							{
								print_date_time(header);
								printf(" ");
								print_sMAC_address(ethernet);
								printf(" -> ");
								print_dMAC_address(ethernet);
								printf(" ");
								print_ethertype(ethernet);
								printf(" ");
								print_length(header);
								printf("\n");
								
								printf("%s:%d", inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));
								printf(" -> ");
								printf("%s:%d", inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport));
								printf(" ");
								printf("TCP \n");

								if(size_payload > 0)
								{
									print_payload(payload, size_payload);
								}

							}
						
						//printf("   Protocol: TCP\n");
						
						break;}
					
					case IPPROTO_UDP:{


						udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
						size_udp = sizeof(udp);
						payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
						size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

						//char *ch;
						ch = payload;
						char ascii_payload[size_payload];
						//int x;
						int y = 0;
						for(x = 0; x < size_payload;x++){
							if(isprint(*ch)){
								ascii_payload[y++] = *ch;
							}
							ch++;
						}

						if(sflag == 1)
						{
							if(size_payload > 0)
							{
								char *ret;
								ret = strstr(ascii_payload, sname);
								//printf("ret = %s\n", ret);

								if(ret)
								{

									//printf("Matched ret\n");
									print_date_time(header);
									printf(" ");
									print_sMAC_address(ethernet);
									printf(" -> ");
									print_dMAC_address(ethernet);
									printf(" ");
									print_ethertype(ethernet);
									printf(" ");
									print_length(header);
									printf("\n");

									printf("%s:%d",inet_ntoa(ip->ip_src),udp->udp_src);
									printf(" -> ");
									printf("%s:%d",inet_ntoa(ip->ip_dst),udp->udp_dst);
									printf(" ");
									printf("UDP \n");

									print_payload(payload, size_payload);

								}

							}
							

						}

						else
						{
							print_date_time(header);
							printf(" ");
							print_sMAC_address(ethernet);
							printf(" -> ");
							print_dMAC_address(ethernet);
							printf(" ");
							print_ethertype(ethernet);
							printf(" ");
							print_length(header);
							printf("\n");
							udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
							size_udp = sizeof(udp);

							printf("%s:%d",inet_ntoa(ip->ip_src),udp->udp_src);
							printf(" -> ");
							printf("%s:%d",inet_ntoa(ip->ip_dst),udp->udp_dst);
							printf(" ");
							printf("UDP \n");

							if(size_payload > 0)
							{
								print_payload(payload, size_payload);

							}

						}
						
						break;}

					case IPPROTO_ICMP:{
						payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8); // Size of UDP header is 8 bytes
						size_payload = ntohs(ip->ip_len) - (size_ip + 8);
						
						//char *ch;
						ch = payload;
						char ascii_payload[size_payload];
						//int x;
						int y = 0;
						for(x = 0; x < size_payload;x++){
							if(isprint(*ch)){
								ascii_payload[y++] = *ch;
							}
							ch++;
						}

						
						if(sflag == 1)
						{
							if(size_payload > 0)
							{
								char *ret;
								ret = strstr(ascii_payload, sname);
								//printf("ret = %s\n", ret);

								if(ret)
								{
									print_date_time(header);
									printf(" ");
									print_sMAC_address(ethernet);
									printf(" -> ");
									print_dMAC_address(ethernet);
									printf(" ");
									print_ethertype(ethernet);
									printf(" ");
									print_length(header);
									printf("\n");

									printf("%s",inet_ntoa(ip->ip_src));
									printf(" -> ");
									printf("%s",inet_ntoa(ip->ip_dst));
									printf(" ");
									printf("ICMP \n");
									print_payload(payload, size_payload);

								}


							}
						}
						else
						{
							print_date_time(header);
							printf(" ");
							print_sMAC_address(ethernet);
							printf(" -> ");
							print_dMAC_address(ethernet);
							printf(" ");
							print_ethertype(ethernet);
							printf(" ");
							print_length(header);
							printf("\n");
									
							printf("%s",inet_ntoa(ip->ip_src));
							printf(" -> ");
							printf("%s",inet_ntoa(ip->ip_dst));
							printf(" ");
							printf("ICMP \n");
							if(payload > 0)
							{
								print_payload(payload, size_payload);
							}
						}
						
						break;}
					
					default:{
						payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
						size_payload = ntohs(ip->ip_len) - (size_ip);
						if(size_payload > 0)
						{
							if(sflag == 1)
							{
								char *ret;
								ret = strstr(payload, sname);
								//printf("ret = %s\n", ret);

								if(ret)
								{
									printf("%s",inet_ntoa(ip->ip_src));
									printf(" -> ");
									printf("%s",inet_ntoa(ip->ip_dst));
									printf("\n");
									print_payload(payload, size_payload);
								}

							}
						}
						
						break;}
						
				}
				}
				return;
		}


int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char error_buffer[PCAP_ERRBUF_SIZE];
	int err = 0, iflag = 0, rflag = 0;
	int c;
	char *rname;
	extern char *optarg;
	extern int optind;
	pcap_t *handle;

	char *dev = NULL;			
			
	//char argss[200];
	char filter_exp[500];
	filter_exp[0] = '\0';

	struct bpf_program fp;			
	bpf_u_int32 mask;			
	bpf_u_int32 net;	


	while ((c = getopt(argc, argv, "i:r:s:")) != -1){
		switch (c) {
		
		case 'i':
			iflag = 1;
			dev = optarg;  //EQUATE TO DEVICE
			break;
		case 's':
			sflag = 1;
			sname = optarg;
			//printf("sname = %s\n", sname);
			break;
		case 'r':
            rflag = 1;
            //printf("rflag set \n");
            rname = optarg;
			break;
		default:
			err = 1;
			break;
		}}
		//printf("number of arguments %d \n",argc);
		//printf("sflag is %s",sname);
		//for loop
		//printf("")
		if(optind < argc){
			for(; optind < argc; optind++){
			//printf("argument: %s \n", argv[optind]);
			//printf("%s",filter_exp);
			strcat(strcat(filter_exp," "), argv[optind]);
		}
		

	}
	//printf(" all args = %s\n", filter_exp);
		
	if(rflag == 1 && iflag == 0){
		handle = pcap_open_offline(rname, error_buffer);
		//printf("handle is set. \n");
	}
	
	if(iflag == 1 && rflag == 0){
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	}
	
	if(rflag == 0 && iflag == 0){
		dev = pcap_lookupdev(errbuf);
		printf("%s",dev);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);

	}

	

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
