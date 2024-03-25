#include <cstdio>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <iostream>
#include "ethhdr.h"
#include "arphdr.h"

struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};

void GetMyMac(char *mymac, const char *dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    uint8_t *mac = (uint8_t *)ifr.ifr_hwaddr.sa_data;
    sprintf(mymac, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void GetMyIp(char *myip, const char *dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    strcpy(myip, inet_ntoa(sin->sin_addr));
}

void SendArpRequest(pcap_t *handle, const char *dev, const char *sender_ip, const char *target_ip, const char *my_mac, const char *my_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(my_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac);
    packet.arp_.sip_ = htonl(Ip(my_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // Unknown at this point
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char dev[IFNAMSIZ];
    printf("%s\n",argv[1]);
    strncpy(dev, argv[1], IFNAMSIZ - 1);
    dev[IFNAMSIZ - 1] = '\0';

    char my_mac[Mac::SIZE];
    char my_ip[Ip::SIZE];
    char *sender_ip = argv[2];
    char *target_ip = argv[3];

    GetMyMac(my_mac, dev);
    GetMyIp(my_ip, dev);

    printf("My Mac: %s\n", my_mac);
    printf("My IP: %s\n", my_ip);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    SendArpRequest(handle, dev, sender_ip, target_ip, my_mac, my_ip);

    pcap_close(handle);
    return 0;
}
