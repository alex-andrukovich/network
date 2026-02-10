#gcc -O3 -march=native -pthread -o arpblast_mt arpblast_mt.c

# Use all cores, batch of 64
#time sudo ./arpblast_mt enp3s0 192

# Or explicitly:
#time sudo ./arpblast_mt enp3s0 192 8 128   # 8 threads, batch 128

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

#define ARP_PKT_SIZE 42
#define DEFAULT_BATCH 64

struct arp_packet {
    struct ether_header eth;
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

struct thread_args {
    int thread_id;
    int cpu_id;
    int ifindex;
    unsigned char src_mac[6];
    unsigned char src_ip[4];
    int first_octet;
    int a_start;
    int a_end;
    int batch_size;
};

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static int sendmmsg_wrapper(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags) {
    return syscall(SYS_sendmmsg, sockfd, msgvec, vlen, flags);
}

static void *worker_thread(void *arg) {
    struct thread_args *ta = (struct thread_args *)arg;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(ta->cpu_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) die("socket");

    struct sockaddr_ll saddr = {0};
    saddr.sll_family   = AF_PACKET;
    saddr.sll_ifindex  = ta->ifindex;
    saddr.sll_halen    = ETH_ALEN;
    memset(saddr.sll_addr, 0xff, 6);

    int batch = ta->batch_size;
    struct arp_packet *pkts = calloc(batch, sizeof(struct arp_packet));
    struct mmsghdr *msgvec  = calloc(batch, sizeof(struct mmsghdr));
    struct iovec   *iovecs  = calloc(batch, sizeof(struct iovec));
    if (!pkts || !msgvec || !iovecs) die("calloc");

    for (int i = 0; i < batch; i++) {
        struct arp_packet *p = &pkts[i];
        memset(p, 0, sizeof(*p));

        memset(p->eth.ether_dhost, 0xff, 6);
        memcpy(p->eth.ether_shost, ta->src_mac, 6);
        p->eth.ether_type = htons(ETHERTYPE_ARP);

        p->arp.htype = htons(1);
        p->arp.ptype = htons(ETHERTYPE_IP);
        p->arp.hlen  = 6;
        p->arp.plen  = 4;
        p->arp.oper  = htons(1);
        memcpy(p->arp.sha, ta->src_mac, 6);
        memcpy(p->arp.spa, ta->src_ip, 4);
        memset(p->arp.tha, 0x00, 6);

        iovecs[i].iov_base = p;
        iovecs[i].iov_len  = ARP_PKT_SIZE;

        memset(&msgvec[i], 0, sizeof(struct mmsghdr));
        msgvec[i].msg_hdr.msg_iov    = &iovecs[i];
        msgvec[i].msg_hdr.msg_iovlen = 1;
        msgvec[i].msg_hdr.msg_name   = &saddr;
        msgvec[i].msg_hdr.msg_namelen= sizeof(saddr);
    }

    unsigned char *tpa0, *tpa1, *tpa2, *tpa3;
    int idx = 0;

    for (int a = ta->a_start; a < ta->a_end; a++) {
        for (int b = 0; b < 256; b++) {
            for (int c = 1; c < 255; c++) {
                struct arp_packet *p = &pkts[idx];
                tpa0 = &p->arp.tpa[0];
                tpa1 = &p->arp.tpa[1];
                tpa2 = &p->arp.tpa[2];
                tpa3 = &p->arp.tpa[3];

                *tpa0 = (unsigned char)ta->first_octet;
                *tpa1 = (unsigned char)a;
                *tpa2 = (unsigned char)b;
                *tpa3 = (unsigned char)c;

                idx++;

                if (idx == batch) {
                    int sent = sendmmsg_wrapper(sockfd, msgvec, batch, 0);
                    if (sent < 0) {
                        // optional: perror("sendmmsg");
                    }
                    idx = 0;
                }
            }
        }
    }

    if (idx > 0) {
        sendmmsg_wrapper(sockfd, msgvec, idx, 0);
    }

    free(pkts);
    free(msgvec);
    free(iovecs);
    close(sockfd);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "Usage: %s <iface> <first_octet> [threads] [batch]\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int first_octet = atoi(argv[2]);
    if (first_octet < 1 || first_octet > 223) {
        fprintf(stderr, "Invalid first octet: %d\n", first_octet);
        return 1;
    }

    int n_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (argc >= 4) {
        n_threads = atoi(argv[3]);
        if (n_threads < 1) n_threads = 1;
    }

    int batch_size = DEFAULT_BATCH;
    if (argc == 5) {
        batch_size = atoi(argv[4]);
        if (batch_size < 1) batch_size = 1;
        if (batch_size > 1024) batch_size = 1024;
    }

    int sock_tmp = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock_tmp < 0) die("socket");

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) die("if_nametoindex");

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock_tmp, SIOCGIFHWADDR, &ifr) < 0) die("SIOCGIFHWADDR");
    unsigned char src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock_tmp, SIOCGIFADDR, &ifr) < 0) die("SIOCGIFADDR");
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    unsigned char src_ip[4];
    memcpy(src_ip, &sin->sin_addr.s_addr, 4);

    close(sock_tmp);

    if (n_threads > 256) n_threads = 256;
    int base = 256 / n_threads;
    int rem  = 256 % n_threads;

    pthread_t *threads = calloc(n_threads, sizeof(pthread_t));
    struct thread_args *targs = calloc(n_threads, sizeof(struct thread_args));
    if (!threads || !targs) die("calloc");

    int a_start = 0;
    for (int i = 0; i < n_threads; i++) {
        int chunk = base + (i < rem ? 1 : 0);
        int a_end = a_start + chunk;

        targs[i].thread_id   = i;
        targs[i].cpu_id      = i;
        targs[i].ifindex     = ifindex;
        memcpy(targs[i].src_mac, src_mac, 6);
        memcpy(targs[i].src_ip, src_ip, 4);
        targs[i].first_octet = first_octet;
        targs[i].a_start     = a_start;
        targs[i].a_end       = a_end;
        targs[i].batch_size  = batch_size;

        if (pthread_create(&threads[i], NULL, worker_thread, &targs[i]) != 0) {
            die("pthread_create");
        }

        a_start = a_end;
    }

    for (int i = 0; i < n_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(targs);
    return 0;
}
