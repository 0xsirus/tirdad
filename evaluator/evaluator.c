/*
	Sirus Shahini
	~cyn
*/

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include<netinet/tcp.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/utsname.h>

#define MAC_LENGTH 6
#define PACKET_SIZE 4096

#define CNORM				"\033[0m"
#define CRED				"\x1b[1;31m"
#define CGREEN				"\x1b[1;32m"

#define TCP_OPT_END      0
#define TCP_OPT_NOP      1
#define TCP_OPT_TS       8

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short int u16;
typedef unsigned char u8;

typedef long s64;
typedef int s32;
typedef short int s16;
typedef char s8;

#define DST_PORT	_const_dst_port
#define SAMPLE_SIZE	10

u16 _const_dst_port;

struct iface{
	char name[255];
	u32 index;
	u8 hw[6];
	int sock;
};

struct comp_stat {
	u8 v4_seq;
	u8 v4_ts;
	u8 v6_seq;
	u8 v6_ts;
} c_stat;

u8 v4_complete = 0;
u8 v6_complete = 0;
u8 ts_disbaled = 0;

struct seq_queue{
	int index;
	u32 q[SAMPLE_SIZE*2];
} v4sq, v6sq;

struct ts_queue{
	int index;
	u32 q[SAMPLE_SIZE*2];
} v4ts, v6ts;

struct result_board{
	s8 v4sq, v4ts, v6sq, v6ts;
} results;

int ts_off_supported = 0;

#define hw_zero	"\x00\x00\x00\x00\x00\x00"

struct transition_dir{
	u8 inc;
	u8 dec;
};

#define DISTANCE_MIN_THRESH	0xFFFF

char *get_buf(u64 size){
	char *buf;

	buf = calloc(size,1);

	if (!buf){
		printf("[!] out of memory\n");
		exit(-1);
	}

	return buf;
}


void _cerr(char *fmt,...){
	int buf_len=2048;
	char * err_format = get_buf(buf_len);

	strcpy(err_format,CRED "[!] " CNORM );

	if (strlen(fmt) + strlen(err_format) < buf_len-1){
		strcat(err_format,fmt);
		strcat(err_format,"\n");

		va_list argp;
		va_start(argp,err_format);
		vfprintf(stderr, err_format,argp);
		va_end(argp);
	}else{
		printf("[!] Err\n");
	}

	exit(-1);
}


void _crep(char *fmt, ...){
	int buf_len=2048;
	char *out = get_buf(buf_len);

	if (!out){
		printf("[!] out of memory");
		exit(-1);
	}

	strcpy(out,"[-] ");
	if(strlen(fmt) + strlen(out) < buf_len-1){
		strcat(out,fmt);
		strcat(out,"\n");

		va_list argp;
		va_start(argp,out);
		vprintf(out,argp);
		va_end(argp);
	}else{
		printf("Debug msg too large.\n");
	}

	free(out);
}


int v4(){
	struct sockaddr_in remote_addr;
	char ip[] = "127.0.0.1";
	int i;
	u16 src_port = 0;

	do{
		src_port = 10000 + (rand() % 50000);
	}while(src_port == _const_dst_port);

	inet_pton(AF_INET,ip,&(remote_addr.sin_addr));
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(DST_PORT);

	for (i=0;i<SAMPLE_SIZE;i++){
		int client = socket(AF_INET,SOCK_STREAM,0);
		int flags = fcntl(client,F_GETFL,0);

		struct sockaddr_in local_addr ;

		if (fcntl(client,F_SETFL,flags | O_NONBLOCK))
		{
			_cerr("fcntl failed\n");
			return -1;
		}

		inet_pton(AF_INET,"0.0.0.0",&(local_addr.sin_addr));

		local_addr.sin_family = AF_INET;

		local_addr.sin_port = htons(src_port);
        	printf("\t[TRIGGER v4] : lo %d\n",src_port);
		if (bind(client , (struct sockaddr*)&local_addr,sizeof local_addr)){
			_cerr("[v4] socket bind: %s",strerror(errno));
			return -1;
		}

		connect(client,(struct sockaddr*)&remote_addr,sizeof remote_addr);
		close(client);
		usleep(10);
	}
	return 0;
}


int v6(){
	int i;
	struct sockaddr_in6 remote_addr;
	char ip[] = "::1";
	u16 src_port = 0;

	do{
		src_port = 10000 + (rand() % 50000);
	}while(src_port == _const_dst_port);

	inet_pton(AF_INET6,ip,&(remote_addr.sin6_addr));
	remote_addr.sin6_family = AF_INET6;
	remote_addr.sin6_port = htons(DST_PORT);

	for (i=0;i<SAMPLE_SIZE;i++){
		struct sockaddr_in6 local_addr ;
		int client = socket(AF_INET6,SOCK_STREAM,0);
		int flags = fcntl(client,F_GETFL,0);

		if (fcntl(client,F_SETFL,flags | O_NONBLOCK))
		{
			printf("fcntl: %s",strerror(errno));
			return -1;
		}
		inet_pton(AF_INET6,"::",&(local_addr.sin6_addr));
		local_addr.sin6_family = AF_INET6;
		local_addr.sin6_port = htons(src_port);

		if (bind(client , (struct sockaddr*)&local_addr,sizeof local_addr)){
			_cerr("[v6] socket bind: %s",strerror(errno));
			return -1;
		}

		printf("\t[TRIGGER v6] : lo %d\n",src_port);
		connect(client,(struct sockaddr*)&remote_addr,sizeof remote_addr);
		close(client);
		usleep(10);
	}

	return 1;
}


void ntoa_mac(void *hw,char *a_mac){
    sprintf(a_mac,"%02X:%02X:%02X:%02X:%02X:%02X",
    	((u8 *)hw)[0],
	((u8 *)hw)[1],
	((u8 *)hw)[2],
	((u8 *)hw)[3],
	((u8 *)hw)[4],
	((u8 *)hw)[5]
    );
}


void ntoa_ip(u8 *raw_ip,char *a_ip){
    strncpy(a_ip,inet_ntoa(*((struct in_addr*)raw_ip)), 20);
}


void bind_to_iface(int sock,u32 if_index){
	struct sockaddr_ll sll;
	sll.sll_ifindex = if_index;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_family = AF_PACKET;

	if (bind(sock,(struct sockaddr*)&sll,sizeof(sll))){
		_cerr("iface bind: %s",strerror(errno));
		exit(-1);
	}
}

int get_loopback(int sock,char *if_name, u8 *ip, u8 *mac,int *iface_index){
	struct if_nameindex *if_list, *if_i;
	if (!(if_list=if_nameindex())){
		return 0;
	}

	for (if_i=if_list; if_i->if_index != 0; if_i++){
		struct ifreq ifc;
		u32 index = if_i->if_index;

		strncpy(ifc.ifr_name, if_i->if_name, IFNAMSIZ-1);
		if (ioctl(sock, SIOCGIFFLAGS, &ifc) < 0){
		    _cerr("ioctl");
		}

		if (ifc.ifr_flags & IFF_LOOPBACK){
			strncpy(if_name, if_i->if_name, IFNAMSIZ-1);
			*iface_index = index;

			strncpy(ifc.ifr_name, if_i->if_name, IFNAMSIZ-1);
			if (ioctl(sock, SIOCGIFHWADDR, &ifc) < 0){
			    _cerr("ioctl");
			}
			memcpy(mac,&ifc.ifr_hwaddr.sa_data,MAC_LENGTH);

			strncpy(ifc.ifr_name, if_i->if_name, IFNAMSIZ-1);
			if (ioctl(sock, SIOCGIFADDR, &ifc) < 0) {
			   _cerr("ioctl");
			}
			memcpy(ip,&(((struct sockaddr_in *)&(ifc.ifr_addr))->sin_addr),4);
		}

		if_freenameindex(if_list);
		return 0;
	}

	if_freenameindex(if_list);
	return -1;
}


unsigned int get_packet_eth_type(u8 *packet){
    struct ether_header *eh = (struct ether_header *) packet;
    return ntohs(eh->ether_type);
}

void add_v4_seq(u32 seq){
	if (c_stat.v4_seq)
		return;
	v4sq.q[v4sq.index++] = seq;
	if (v4sq.index == SAMPLE_SIZE){
		c_stat.v4_seq = 1;
		_crep("V4 SEQ - Capture complete");
	}
}

void add_v6_seq(u32 seq){
	if (c_stat.v6_seq)
		return;
	v6sq.q[v6sq.index++] = seq;
	if (v6sq.index == SAMPLE_SIZE){
		c_stat.v6_seq = 1;
		_crep("V6 SEQ - Capture complete");
	}
}

void add_v4_ts(u32 ts){
	if (c_stat.v4_ts)
		return;
	v4ts.q[v4ts.index++] = ts;
	if (v4ts.index == SAMPLE_SIZE){
		c_stat.v4_ts = 1;
		_crep("V4 TS - Capture complete");
	}
}

void add_v6_ts(u32 ts){
	if (c_stat.v6_ts)
		return;
	v6ts.q[v6ts.index++] = ts;
	if (v6ts.index == SAMPLE_SIZE){
		c_stat.v6_ts = 1;
		_crep("V6 TS - Capture complete");
	}
}

void process_ts(u8 *tcph, int type){
	u8 *opts_start  = tcph + sizeof(struct tcphdr);
	u8 *opts_end = tcph + ((struct tcphdr*)tcph)->doff*4;
	u8 *opt = opts_start;
	long ts = -1;

	if (ts_disbaled || !ts_off_supported)
		return;

	while (opt < opts_end){
		u8 len;
		u8 kind = opt[0];

		if (kind == TCP_OPT_END)
			break;

		if (kind == TCP_OPT_NOP){
			opt++;
			continue;
		}

		if (opt + 1 > opts_end)
			break;

		len = opt[1];

		if (len<2 || opt+len > opts_end)
			break;

		if (kind == TCP_OPT_TS){
			ts = *((u64*) (opt + 2));
			break;
		}
		opt+=len;
	}

	if (ts == -1){
		ts_disbaled = 1;
	}
	else{
		u32 ts_32 = ntohl((u32)ts);

		if (type==4)
			add_v4_ts(ts_32);
		else
			add_v6_ts(ts_32);
	}
}


void parse_v4_packet(u8 *packet){
	struct iphdr *iph = (struct iphdr *) (packet + sizeof(struct ether_header));
	if (iph->protocol != IPPROTO_TCP)
		return;
	struct tcphdr* tcph=(struct tcphdr*)(packet +
		sizeof(struct ether_header) +
		sizeof(struct iphdr));

	if (ntohs(tcph->dest ) != DST_PORT)
		return;

	u32 seq = ntohl(tcph->seq);
	add_v4_seq(seq);
	process_ts((u8*)tcph,4);


}


int v6_proto_terminal(u8 next_header) {
    switch (next_header) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ICMPV6:
        case IPPROTO_NONE:
            return 1;
        default:
            return 0;
    }
}


void parse_v6_packet(u8 *packet){
	struct ipv6hdr *ip6h = (struct ipv6hdr *)(packet + sizeof(struct ether_header));
	u64 offset = sizeof(struct ether_header) + sizeof(struct ipv6hdr);
    	u8 next_header = ip6h->nexthdr;

	while (!v6_proto_terminal(next_header) && offset < PACKET_SIZE)
	{
		uint8_t *ext_hdr = packet + offset;
		int hdr_len = (ext_hdr[1] + 1) * 8;

		next_header = ext_hdr[0];
		offset += hdr_len;
	}

	if (next_header == IPPROTO_TCP) {
		struct tcphdr *tcph = (struct tcphdr *)(packet + offset);

		if (ntohs(tcph->dest ) != DST_PORT)
			return;

        	u32 seq = ntohl(tcph->seq);
        	add_v6_seq(seq);
        	process_ts((u8*)tcph,6);
	}
}


int validate_queue(u32 *q, int size){
	int i;
	struct transition_dir dir;
	u8 distance_satisfied = 0;

	memset(&dir,0,sizeof(dir));

	for (i=1; i<size; i++){
		if (!distance_satisfied){
			int distance = abs((int)q[i] - (int)q[i-1]);

			if (distance >= DISTANCE_MIN_THRESH)
				distance_satisfied = 1;
		}

		if (q[i] < q[i-1])
			dir.dec = 1;
		else if (q[i] > q[i-1])
			dir.inc = 1;
	}

	return (distance_satisfied &&
		dir.inc &&
		dir.dec);
}


char *get_verb(s8 stat){
	switch (stat){
	case -1:
		return "N/A";
	case 0:
		return CRED"VULNERABLE"CNORM;
	case 1:
		return CGREEN"OK"CNORM;
	}

	return "";
}


void display_report(){
	printf("ISN:\n");
	printf("\tv4: [%s]\n", get_verb(results.v4sq));
	printf("\tv6: [%s]\n\n", get_verb(results.v6sq));

	printf("Timestamp:\n");
	printf("\tv4: [%s]\n", get_verb(results.v4ts));
	printf("\tv6: [%s]\n", get_verb(results.v6ts));

}


void print_q(){
	int i ;

	printf("v4seq:\n");
	for (i=0;i<10;i++)
		printf(">> %x \n",v4sq.q[i]);

	printf("v6seq:\n");
	for (i=0;i<10;i++)
		printf(">> %x \n",v6sq.q[i]);

	printf("v4ts:\n");
	for (i=0;i<10;i++){
		printf(">> %x \n",v4ts.q[i]);
	}

	printf("v6ts:\n");
	for (i=0;i<10;i++)
		printf(">> %x \n",v6ts.q[i]);
}


void analyze_result(){
	_crep("Analyzing samples\n");

	results.v4sq = validate_queue(v4sq.q, v4sq.index);

	if (ts_off_supported)
		results.v4ts = validate_queue(v4ts.q, v4ts.index);
	else
		results.v4ts = -1;

	results.v6sq = validate_queue(v6sq.q, v6sq.index);

	if (ts_off_supported)
		results.v6ts = validate_queue(v6ts.q, v6ts.index);
	else
		results.v6ts = -1;

	display_report();
}


void *watcher(void *arg){
	struct sockaddr_ll socket_adr;
	struct sockaddr_in peer_adr;
	unsigned int adr_size = sizeof(struct sockaddr);
	struct iface ifc = *(struct iface*) arg;
	u8 packet[PACKET_SIZE];

	socket_adr.sll_ifindex = ifc.index;
	socket_adr.sll_halen = ETH_ALEN;
	memcpy(socket_adr.sll_addr,hw_zero,MAC_LENGTH);

	while(1){
		adr_size = sizeof(struct sockaddr);
		int n=recvfrom(ifc.sock,packet,PACKET_SIZE,0,(struct sockaddr*)&peer_adr,&adr_size);
		if (n<1)
			_cerr("recv: %s",strerror(errno));
		if (((struct sockaddr_ll*)&peer_adr)->sll_pkttype != PACKET_OUTGOING)
			continue;

		int eth_hdr_type = get_packet_eth_type(packet);

		if (eth_hdr_type==0x800)
			parse_v4_packet(packet);
		else if (eth_hdr_type==0x86dd)
			parse_v6_packet(packet);

		if (c_stat.v4_seq &&
			c_stat.v4_ts &&
			c_stat.v6_seq &&
			c_stat.v6_ts){

			analyze_result();
			return 0;
		}
	}
}


void *time_check(void *arg){
	time_t start = time(0);
	while (1){
		if (time(0) - start > 10){
			_cerr("Timer exhuasted. Potential packet loss");
		}
		sleep(1);
	}
}


void check_kernel(){
	struct utsname info;
	int result;
	char build_version[64];
	int major, minor, patch;

	result = uname(&info);
	if (result)
		_cerr("uname failed");

	sscanf(info.release,"%d.%d.%d", &major, &minor, &patch);
	sprintf(build_version, "%d.%d.%d", major, minor, patch);
	_crep("Kernel: %s" , build_version);
	if (major <6)
		ts_off_supported = 0;
	else if (major > 6)
		ts_off_supported = 1;
	else if(minor < 18)
		ts_off_supported = 0;
	else if (minor > 18)
		ts_off_supported = 1;
	else if (patch >= 17)
		ts_off_supported = 1;
	else
		ts_off_supported =0;

	if (!ts_off_supported){
		_crep("Timestamp offset randomization is not supported in this system.");
		c_stat.v4_ts = 1;
		c_stat.v6_ts = 1;
		return;
	}

	if (ts_off_supported){
		int fd = open("/proc/sys/net/ipv4/tcp_timestamps", O_RDONLY);
		if (fd<0)
			_cerr("open");
		char c;
		read(fd,&c,1);
		close(fd);

		if (c != '1')
			ts_off_supported = 0;
	}

	if (!ts_off_supported){
		_crep("sysctl_tcp_timestamps is not set to 1. Will skip TS_OFF tests.");
		c_stat.v4_ts = 1;
		c_stat.v6_ts = 1;
	}
}


int main(int argc, char **argv){
	pthread_t tid_w, tid_t;
	char if_name[IFNAMSIZ] = {0};
	u8 iface_ip[4];
	u8 iface_mac[6];
	char iface_a_mac[20] = {0};
	char iface_a_ip[20] = {0};
	u32  iface_index;
	int sock = -1;
	struct iface ifc;;
	int r=0;

	if (getuid())
		_cerr("Run as root");

	sock = socket( AF_PACKET , SOCK_RAW ,htons(ETH_P_ALL));

	if (sock < 0)
		_cerr("socket()");

	/*
		Any interface can be used. Transport layer is processed before routing takes
		place. Sequence generator functions are the same.
		No external connection is necessary. We choose the system loopback device (127.0.0.1)
		for these tests.
	*/
	r = get_loopback(sock, if_name, iface_ip, iface_mac, &iface_index);
	if (r)
		_cerr("device enumeration failed.");

	ntoa_mac(iface_mac,iface_a_mac);
	ntoa_ip(iface_ip,iface_a_ip);
	printf("******\n%s\n\t%s\n\tiface index:%u\n\t%s\n******\n",if_name,iface_a_mac,iface_index,iface_a_ip);
	ifc.index = iface_index;
	memcpy(ifc.hw,iface_mac,6);
	strncpy(ifc.name,if_name,20);
	ifc.sock=sock;

	bind_to_iface(sock, iface_index);

	srand(time(0));

	if (pthread_create(&tid_w, 0, watcher, (void *)&ifc))
		_cerr("pthread_create");

	if (pthread_create(&tid_t, 0, time_check, 0))
		_cerr("pthread_create");

	v4sq.index = 0;
	v6sq.index = 0;
	v4ts.index = 0;
	v6ts.index = 0;

	memset(&c_stat,0,sizeof(c_stat));

	check_kernel();

	_const_dst_port = 20000 + (rand() % 60000);

	_crep("Starting TCP timer leakage tests");
	_crep("If tirdad is running you should see OK in test results.\n");

	v4();
	v6();

	pthread_join(tid_w, 0);

	write(1,"\n\n",3);
	_crep("Done.");

	return 0;
}

