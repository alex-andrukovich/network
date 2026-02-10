### gcc -O3 -march=native -o arpblast arpblast.c
### to test sudo ./arpblast enp3s0 192
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define ARP_PKT_SIZE 42

struct arp_packet {
    struct ethhdr eth;
    struct {
        uint16_t htype;
        uint16_t ptype;
        uint8_t  hlen;
        uint8_t  plen;
        uint16_t oper;
        unsigned char sha[6];
        unsigned char spa[4];
        unsigned char tha[6];
        unsigned char tpa[4];
    } arp;
} __attribute__((packed));

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <iface> <first_octet>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int first_octet = atoi(argv[2]);
    if (first_octet < 1 || first_octet > 223) {
        fprintf(stderr, "Invalid first octet: %d\n", first_octet);
        return 1;
    }

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) die("socket");

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) die("if_nametoindex");

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) die("SIOCGIFHWADDR");
    unsigned char src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) die("SIOCGIFADDR");
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    unsigned char src_ip[4];
    memcpy(src_ip, &sin->sin_addr.s_addr, 4);

    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family   = AF_PACKET;
    saddr.sll_ifindex  = ifindex;
    saddr.sll_halen    = ETH_ALEN;
    memset(saddr.sll_addr, 0xff, 6); // broadcast

    struct arp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    // Ethernet header
    memset(pkt.eth.h_dest, 0xff, 6);          // broadcast
    memcpy(pkt.eth.h_source, src_mac, 6);     // our MAC
    pkt.eth.h_proto = htons(ETH_P_ARP);

    // ARP header
    pkt.arp.htype = htons(ARPHRD_ETHER);
    pkt.arp.ptype = htons(ETH_P_IP);
    pkt.arp.hlen  = 6;
    pkt.arp.plen  = 4;
    pkt.arp.oper  = htons(ARPOP_REQUEST);
    memcpy(pkt.arp.sha, src_mac, 6);
    memcpy(pkt.arp.spa, src_ip, 4);
    memset(pkt.arp.tha, 0x00, 6);            // unknown target MAC

    unsigned char *tpa = pkt.arp.tpa;

    for (int a = 0; a < 256; a++) {
        for (int b = 0; b < 256; b++) {
            for (int c = 1; c < 255; c++) {
                tpa[0] = (unsigned char)first_octet;
                tpa[1] = (unsigned char)a;
                tpa[2] = (unsigned char)b;
                tpa[3] = (unsigned char)c;

                ssize_t sent = sendto(sockfd, &pkt, ARP_PKT_SIZE, 0,
                                      (struct sockaddr *)&saddr, sizeof(saddr));
                if (sent < 0) {
                    // You can choose to die here or just continue
                    // die("sendto");
                    continue;
                }
            }
        }
    }

    close(sockfd);
    return 0;
}
