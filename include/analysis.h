#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <pcap.h>

extern int total_packets;
extern int total_ip_packets;
extern int total_tcp_packets;
extern int total_udp_packets;

void print_packet_info(const struct pcap_pkthdr *pkthdr, const u_char *packet);
void extract_headers(const u_char *packet, int packet_length);
void detect_protocols(const u_char *packet, int packet_length);
void calculate_statistics(const u_char *packet, int packet_length);
void reset_statistics();

#endif /* ANALYSIS_H */
