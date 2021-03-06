#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ether.h>     // for either_ntoa
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stddef.h>



#define SIZE_ETHER 14

typedef struct {
	unsigned char dst_eth_addr[6];
	unsigned char src_eth_addr[6];
	unsigned short eth_type;
} __attribute__((packed)) _eth_set;     
// __attribute__((packed))  is advised by teammates

typedef struct {
	unsigned char ip_version:4;
	unsigned char ip_hl:4;
	unsigned char ip_tos;
	unsigned char ip_tmp;
	unsigned short ip_len;
	unsigned char ip_id[2];
	unsigned char ip_flag[2];
	unsigned char ip_ttl;
	unsigned char ip_p;
	unsigned char ip_cksum[1];
	struct in_addr ip_src;
	struct in_addr ip_dst;
	//unsigned char ip_src_addr[4];
	//unsigned char ip_dst_addr[4];
} __attribute__((packed)) _ip_set;
//
typedef struct {
	unsigned short tcp_src_port;
	unsigned short tcp_dst_port;
	unsigned char sq_num[4];
	unsigned char ack_num[4];
	unsigned char offset:4;
	unsigned char reserved:4;
	unsigned char tcp_flags;
	unsigned char window_s[2];
	unsigned char tcp_cksum[2];
	unsigned char urgent_pt[2];
}  __attribute__((packed)) _tcp_set;

int main(int argc, char *argv[]){
	printf("*START*");
	pcap_t *handle;			
	char *dev;			
	char errbuf[PCAP_ERRBUF_SIZE];	
	struct bpf_program fp;	
	char filter_exp[] = "port 80";	

	bpf_u_int32 mask;	
	bpf_u_int32 net;		
	struct pcap_pkthdr *header;
	int ck_packet;	
	const u_char *packet;		
	
	// ether packet 14 bye
	_eth_set *_eth;
	_ip_set *_ip;
	//ip *_ip;
	_tcp_set *_tcp;
	char *_data;
	int hdr_length;

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */


//START
	while(1){
		ck_packet = pcap_next_ex(handle, &header,&packet);
		if(ck_packet==0){
			printf("ck_packet=0\n");
			continue;
		}
		else if(ck_packet==1){
			_eth=(_eth_set*)(packet);
			//packet=packet+14;   //if use in below 'packet+14' it means  address+14.  so did in here.
			//_ip=(struct _ip_set*)(&(packet[SIZE_ETHER]));
			_ip=(_ip_set*)(&(packet[SIZE_ETHER]));
			//packet=packet+20;  // same with above commend
			_tcp=(_tcp_set*)(&(packet[SIZE_ETHER+(_ip->ip_hl)*4]));
			_data=(&(packet[SIZE_ETHER+(_ip->ip_hl)*4+(_tcp->offset)*4]));

			//printf("\nIP hl = %d\n", _ip->ip_ihl * 4);
/*
			printf("\ndst MAC : ");
			for(int i = 0; i<6; i++){	
				printf("%02x ", _eth->dst_eth_addr[i]);
			}
			
			printf("\nsrc MAC : ");
				for(int i = 0; i<6; i++){
				printf("%02x ", _eth->src_eth_addr[i]);
			}
			printf("\n");

*/
			/*
			int i=0;
			for(i=0;i<50;i++){
				if(i%16 == 0)
					printf("\n");
				printf("%02x ", packet[i]);
			}
			*/

			printf("=====================================================\n");
			printf("dst MAC : %s\n", ether_ntoa((_eth_set*) _eth->dst_eth_addr));
			printf("src MAC : %s\n", ether_ntoa((_eth_set*) _eth->src_eth_addr));
			printf("Type    : %04x\n\n", ntohs(_eth->eth_type));

/*		
			printf("dst IP : ");
			for(int i=0; i<4; i++){
				printf("%d ",_ip->ip_dst_addr[i]);
			}
			printf("\nsrc IP : ");
			for(int i=0; i<4; i++){
				printf("%d ", _ip->ip_src_addr[i]);
			}
*/		
			//char *d_addr=(_ip->ip_dst_addr);
			
			printf("dst IP : %s\n", inet_ntoa( _ip->ip_dst));
			printf("src IP : %s\n", inet_ntoa( _ip->ip_src));
			printf("PROTOCOL : %d\n", _ip->ip_p);

			//printf("src IP : %x\n", inet_ntoa((_ip_set*) _ip->ip_src_addr));

			printf("\ndst Port : %hu\n",ntohs(_tcp->tcp_dst_port));
			printf("src Port : %hu\n",ntohs(_tcp->tcp_src_port));
			
			hdr_length=SIZE_ETHER+(_ip->ip_hl)*4+(_tcp->offset)*4;

//////////////////////

			printf("\nTotal Length : %x\n", (_ip->ip_len));
			//printf("eth+ip Header Length : %d\n",hdr_length);
			printf("ToS : %02x \n",_ip->ip_tos);
			printf("Offset of : %02d\n",offsetof(_ip_set,ip_len));
			printf("ip Header Length : %d \n", _ip->ip_hl*4);
			printf("Data Length : %d\n", ntohs(_ip->ip_len)-hdr_length);
			printf("DATA : ");
///////////////////////			
			/*
			for(int i=0; i<(_ip->ip_len)-hdr_length; i++){
			//	printf("%02x ",_data[i]);
			}
			*/

		}
		else{
			printf("ck_packout wrong\n");
			break;
		}

		
		//printf("\n\n*END*\n\n");
		
			printf("\n\n");

			for(int i=1; i<=60; i++){
				if(i % 16 == 0)
					printf("\n");
				else
					printf("%02x ", packet[i - 1]);
			}
			printf("\n\n");
		
	}
	/* Print its length */
	//printf("Jacked a packet with length of [%d]\n", header.len);
	/* And close the session */

	pcap_close(handle);
	return(0);
 }
		
	