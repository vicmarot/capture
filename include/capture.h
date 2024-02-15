#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdbool.h>
#include <stdlib.h>
#include <pcap.h>


#define MAX_ADAPTER_NAME_LEN 256
#define MAX_COMMAND_LEN 50

#define CONFIG_FILE "config/config.txt"

typedef struct {
    bool print_packet_info;
    bool extract_headers;
    bool detect_protocols;
    bool calculate_statistics;
    pcap_t* handle;
} CaptureOptions;

void start_packet_capture(CaptureOptions *options);

#endif
