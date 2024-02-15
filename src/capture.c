#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <signal.h> 

#include "capture.h"
#include "utils.h"
#include "analysis.h"

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    CaptureOptions *options = (CaptureOptions *)user_data;
    if (stop_capture) {
        pcap_breakloop((pcap_t *)options->handle);
    }

    printf("Captured a packet\n");

    if (options->print_packet_info) {
        print_packet_info(pkthdr, packet);
    }
    if (options->extract_headers) {
        extract_headers(packet, pkthdr->len);
    }
    if (options->detect_protocols) {
        detect_protocols(packet, pkthdr->len);
    }
    if (options->calculate_statistics) {
        calculate_statistics(packet, pkthdr->len);
    }
}

void start_packet_capture(CaptureOptions *options) {
    char adapter_name[MAX_ADAPTER_NAME_LEN];
    char errbuf[PCAP_ERRBUF_SIZE];
    

    // Register signal handler for SIGINT (Ctrl+C)
    signal(SIGINT, sigint_handler);

    // Read network adapter from configuration file
    FILE *config_file = fopen(CONFIG_FILE, "r");
    if (config_file == NULL) {
        fprintf(stderr, "Error opening configuration file\n");
        return;
    }
    char line[MAX_ADAPTER_NAME_LEN];
    while (fgets(line, MAX_ADAPTER_NAME_LEN, config_file) != NULL) {
        if (strstr(line, "NETWORK_ADAPTER=") != NULL) {
            sscanf(line, "NETWORK_ADAPTER=%s", adapter_name);
            break;
        }
    }
    fclose(config_file);


    adapter_name[strcspn(adapter_name, "\n")] = 0;

    options->handle = pcap_open_live(adapter_name, BUFSIZ, 1, 1000, errbuf);

    if (options->handle == NULL) {
        fprintf(stderr, "Failed to open network adapter: %s\n", errbuf);
        return;
    }

    reset_statistics();
    reset_sigint_handler();
    // Start packet capture
    pcap_loop(options->handle, 0, packet_handler, (u_char*) options);

    // Close the network adapter after finishing capture
    pcap_close(options->handle);
}
