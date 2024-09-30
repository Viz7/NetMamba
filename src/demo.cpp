#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <linux/if_ether.h>
#include <ctype.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <map>
#include <cstring>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>

using namespace std;

void print_data(const unsigned char *data, unsigned int len) {
    int i;
    printf("receive %d bytes\n***************************payload****************************\n", len);
    for (i = 0; i < len; i++)
    {
        printf("%02X", data[i]); // 输出十六进制值，并在值之间添加空格
        if ((i + 1) % 16 == 0)
        {
            printf("\t");
            for (int j = i - 15; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 126)
                {
                    printf("%c", data[j]); // 输出 ASCII 字符（如果可打印）
                }
                else
                {
                    printf(".");
                }
                if ((j + 1) % 16 == 0)
                {
                    printf("\n"); // 在每行的末尾打印换行符
                }
            }
        }
    }
    printf("\n");
}

struct ethheader
{
    u_char ether_dhost[6];
    // 目的mac地址
    u_char ether_shost[6];
    // 源mac地址
    u_short ether_type;
};

/* IP Header */
struct ipheader
{
    unsigned char iph_ihl : 4,       // IP header length
        iph_ver : 4;                 // IP version
    unsigned char iph_tos;           // Type of service
    unsigned short int iph_len;      // IP Packet length (data + header)
    unsigned short int iph_ident;    // Identification
    unsigned short int iph_flag : 3, // Fragmentation flags
        iph_offset : 13;             // Flags offset
    unsigned char iph_ttl;           // Time to Live
    unsigned char iph_protocol;      // Protocol type
    unsigned short int iph_chksum;   // IP datagram checksum
    struct in_addr iph_sourceip;     // Source IP address
    struct in_addr iph_destip;       // Destination IP address
};

struct tcpheader
{
    unsigned short sport;    // 源端口
    unsigned short dport;    // 目标端口
    unsigned int seq;        // 序列号
    unsigned int ack_seq;    // 确认号
    unsigned char len;       // 首部长度
    unsigned char flag;      // 标志位
    unsigned short win;      // 窗口大小
    unsigned short checksum; // 校验和
    unsigned short urg;      // 紧急指针
};

/* UDP Header */
struct udphdr
{
    u_int16_t sport; /* source port */
    u_int16_t dport; /* destination port */
    u_int16_t ulen;  /* udp length */
    u_int16_t sum;   /* udp checksum */
};

struct tup {
	uint32_t src;
	uint16_t sport;
	uint32_t dst;
	uint16_t dport;
	uint16_t proto;

	bool operator <(const tup &t) const {
		if (src != t.src) return src < t.src;
		if (sport != t.sport) return sport < t.sport;
		if (dst != t.dst) return dst < t.dst;
		if (dport != t.dport) return dport < t.dport;
		return proto < t.proto;
	}
};

struct Packets {
	int num;
	unsigned char *content[5];

	Packets() {
		num = 0;
	}

	void add (unsigned char *packet_content, unsigned short len) {
		if(num < 5) {
			content[num] = new unsigned char[500];
			memset(content[num], 0, 500);
			memcpy(content[num], packet_content, min((unsigned short)500, len));
			// print_data(packet_content, min((unsigned short)500, len));
			// print_data(content[num], min((unsigned short)500, len));
		}
		++num;
	}
};

int shm_fd;
void *shm_ptr;

#define MAX_PKT_BURST 32
#define SHM_SIZE (2L * 1024 * 1024 * 1024)  // 设置为2GB
#define SHM_NAME "share_memory.dat"

struct SharedMemoryQueue {
    size_t read_index;
    size_t write_index;
    size_t size;
    char buffer[];
};

SharedMemoryQueue* shm_queue;

void init_shared_memory() {
    shm_fd = open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        exit(1);
    }

    if (ftruncate(shm_fd, SHM_SIZE) == -1) {
        perror("ftruncate");
        exit(1);
    }

    // shm_ptr = mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    // if (shm_ptr == MAP_FAILED) {
    //     perror("mmap");
    //     exit(1);
    // }

    shm_queue = (SharedMemoryQueue *)mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    shm_queue->read_index = 0;
    shm_queue->write_index = 0;
    shm_queue->size = SHM_SIZE - sizeof(struct SharedMemoryQueue);

    printf("\nSet shared memory successfully, size is %u.\n", shm_queue->size);
}

void write_in_shared_memory(void *pkt_data, size_t pkt_len) {
    size_t available_space;
    if (shm_queue->write_index >= shm_queue->read_index) {
        available_space = shm_queue->size - (shm_queue->write_index - shm_queue->read_index);
    } else {
        available_space = shm_queue->read_index - shm_queue->write_index;
    }
    size_t total_size_needed = sizeof(pkt_len) + pkt_len;

    if (total_size_needed <= available_space) {

        size_t offset = shm_queue->write_index % shm_queue->size;
        memcpy(&shm_queue->buffer[offset], &pkt_len, sizeof(pkt_len));
        offset = (offset + sizeof(pkt_len)) % shm_queue->size;

        memcpy(&shm_queue->buffer[offset], pkt_data, pkt_len);
        shm_queue->write_index = (shm_queue->write_index + total_size_needed) % shm_queue->size;
    } else {
        printf("shm_queue->read_index: %u, shm_queue->write_index: %u, shm_queue->size: %u.\n", shm_queue->read_index, shm_queue->write_index, shm_queue->size);
        printf("No space left in buffer, available_space: %u, total_size_needed: %u.\n", available_space, total_size_needed);
        exit(1);
    }

    printf("\n%u ~ %u ~ pktlen: %u.\n", shm_queue->read_index, shm_queue->write_index, pkt_len);
}

int raw_packet_to_string(unsigned char *packet, unsigned char *&header, unsigned char *&payload, bool remove_ip = true, bool keep_payload = true) {
	ipheader *ip = (ipheader *)packet;
	if (remove_ip) {
		ip->iph_sourceip.s_addr = ip->iph_destip.s_addr = 0;
	}
	header = (unsigned char *)ip;
	tcpheader *tcp = (tcpheader *)(packet + ip->iph_ihl * 4);
	payload = (unsigned char *)tcp + tcp->len / 16 * 4;
	return ip->iph_ihl * 4 + tcp->len / 16 * 4;
}

unsigned char *read_5hp_list(unsigned char * packets[], bool remove_ip = true, bool keep_payload = true) {
	int flow_string_length = 3200;
	int flow_packet_num = 5;
	unsigned char *res = new unsigned char[1600];
	memset(res, 0, sizeof (res));
	for (int i = 0; i < flow_packet_num; ++i) {
		unsigned char *header, *payload;
		int header_len = raw_packet_to_string(packets[i], header, payload, remove_ip, keep_payload);
		for (int p = 0; p < min(80, header_len); ++p) res[i * 320 + p] = header[p];
		for (int p = 0; p < 240; ++p) res[i * 320 + 80 + p] = payload[p];
	}
	return res;
}

void handler(unsigned char *argument,const struct pcap_pkthdr *packet_header,const unsigned char *packet_content) {
	// if(packet_header->caplen < 500)
	// print_data(packet_content, packet_header->caplen);
	static map<tup, Packets> m;

	ethheader *eth = (ethheader *)(packet_content + sizeof(u_char) * 2);
	printf("Source MAC: ");
	for (int i = 0; i < 6; ++i) printf("%02x%c", eth->ether_dhost[i], " \n"[i == 5]);
	printf("Destination MAC: ");
	for (int i = 0; i < 6; ++i) printf("%02x%c", eth->ether_shost[i], " \n"[i == 5]);
	printf("Ethernet Type: %04x\n", ntohs(eth->ether_type));

	tup t;

	if (ntohs(eth->ether_type) == 0x0800) {
		printf("Protocal: IPV4\n");
		ipheader *ip = (ipheader *)(packet_content + sizeof(ethheader) + sizeof(u_char) * 2);
		printf("%d\n", ip->iph_ihl);
		printf("From: %s\n", inet_ntoa(ip->iph_sourceip));
		printf("To: %s\n", inet_ntoa(ip->iph_destip));
		t.src = ip->iph_sourceip.s_addr;
		t.dst = ip->iph_destip.s_addr;
		t.proto = ip->iph_protocol;
		int payload_length;
		struct tcpheader *tcp;
		struct udphdr *udp;
		switch (ip->iph_protocol) {
			case IPPROTO_TCP:
				printf("Protocol: TCP\n");
				tcp = (struct tcpheader *) (packet_content + sizeof(ethheader) + ip->iph_ihl * 4 + sizeof(u_char) * 2);
				printf("From: %d\n", ntohs(tcp->sport));
				printf("To: %d\n", ntohs(tcp->dport));
				printf("len: %d\n", tcp->len / 16);
				t.sport = ntohs(tcp->sport);
				t.dport = ntohs(tcp->dport);

				m[t].add ((unsigned char *) ip, ip->iph_len);
				if (m[t].num == 5) {
					unsigned char *png = read_5hp_list(m[t].content);
					write_in_shared_memory(png, 1600);
				}
				
				// unsigned char *tcp_data = (unsigned char *) (tcp) + (tcp->len * 4);
				// payload_length = packet_header->len;
				break;
			case IPPROTO_UDP:
				printf("Protocol: UDP\n");
				udp = (struct udphdr *) (packet_content + sizeof(ethheader) + ip->iph_ihl * 4 + sizeof(u_char) * 2);
				printf("From: %d\n", ntohs(udp->sport));
				printf("To: %d\n", ntohs(udp->dport));
				t.sport = ntohs(udp->sport);
				t.dport = ntohs(udp->dport);

				// unsigned char *udp_data = (unsigned char *) (tudp) + sizeof(udphdr);
				// payload_length = packet_header->len;
				return;
				break;
			case IPPROTO_ICMP:
				// printf("Protocol: ICMP\n");
				return;
				break;
			default:
				// printf("Protocol: others\n");
				return;
				break;
		}
	} else if (ntohs(eth->ether_type) == 0x0806) {
		printf("Protocol: ARP\n");
		return;
	} else if (ntohs(eth->ether_type) == 0x86DD) {
		printf("Protocol: IPV6\n");
		//TODO
		return;
	}
}

int main() {
	
    init_shared_memory();

	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	int num = pcap_findalldevs(&alldevs, errbuf);
	if (num == -1) {
		cout << "Error in pcap_findalldevs: " << errbuf << endl;
		return 0;
	}

	pcap_if_t *p = alldevs;
	char *device = p->name;
	cout << p->name << endl;
	// while(p != NULL) {
	// 	cout << p->name << endl;
	// 	p = p->next;
	// }

	bpf_u_int32 netp = 0, maskp = 0;
	if (pcap_lookupnet(device, &netp, &maskp, errbuf)) {
		cout << "Error in pcap_lookupnet: " << errbuf << endl;
		return 0;
	}
	cout << netp << ' ' << maskp << endl;

	pcap_t *pcap_handle = pcap_open_live("any", 65535, 1, 0, errbuf);

	cout << "ok" << endl;

	pcap_pkthdr hdr;
	const unsigned char *p_packet_content = NULL;

	if (pcap_loop(pcap_handle, -1, handler, NULL) < 0) {
		cout << "Error" << endl;
	}
	return 0;
}