#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


#include "analysis.h"


int total_packets;
int total_ip_packets;
int total_tcp_packets;
int total_udp_packets;

void print_packet_info(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("Packet captured. Length: %d\n", pkthdr->len);

    // Extract Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            eth_header->ether_shost[0], eth_header->ether_shost[1],
            eth_header->ether_shost[2], eth_header->ether_shost[3],
            eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            eth_header->ether_dhost[0], eth_header->ether_dhost[1],
            eth_header->ether_dhost[2], eth_header->ether_dhost[3],
            eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
}

void extract_headers(const u_char *packet, int packet_length) {

    const struct ether_header *ethernet_header;
    const struct ip *ip_header;
    const struct tcphdr *tcp_header;
    // const struct udphdr *udp_header;

    ethernet_header = (struct ether_header*)(packet);

    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        
        printf("IP src: %s\n", inet_ntoa(ip_header->ip_src));
        printf("IP dst: %s\n", inet_ntoa(ip_header->ip_dst));

        if (ip_header->ip_p == IPPROTO_TCP) {
            tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
            
            printf("TCP src port: %d\n", ntohs(tcp_header->th_sport));
            printf("TCP dst port: %d\n", ntohs(tcp_header->th_dport));
        }
    }
}

void detect_protocols(const u_char *packet, int packet_length) {
    
    const struct ether_header *ethernet_header = (struct ether_header*) packet;
    printf("Ethernet protocol: ");

    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
        printf("IP\n");
        const struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        
        printf("IP protocol: ");
        switch (ip_header->ip_p) {
            case IPPROTO_TCP:
                printf("TCP\n");
                break;
            case IPPROTO_UDP:
                printf("UDP\n");
                break;
            default:
                printf("Other\n");
                break;
        }

    } else {
        printf("Other\n");
    }
}


void calculate_statistics(const u_char *packet, int packet_length) {
    total_packets++;

    const struct ether_header *ethernet_header = (struct ether_header*) packet;
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
        total_ip_packets++;
        const struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        if (ip_header->ip_p == IPPROTO_TCP) {
            total_tcp_packets++;
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            total_udp_packets++;
        }
    }

    printf("Total packets: %d, IP packets: %d, TCP packets: %d, UDP packets: %d\n",
           total_packets, total_ip_packets, total_tcp_packets, total_udp_packets);
}

void reset_statistics() {
    total_packets = 0;
    total_ip_packets = 0;
    total_tcp_packets = 0;
    total_udp_packets = 0;
}