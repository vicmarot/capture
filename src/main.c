#include <stdio.h>
#include <string.h>
#include "capture.h"

#define MAX_COMMAND_LEN 50


void print_menu(CaptureOptions *options) {
    printf("Packet Capture Program Menu:\n");
    printf("1. Start packet capture\n");
    printf("2. Print packet information");
    options->print_packet_info ? printf("[ON]\n") : printf("[OFF]\n");
    printf("3. Extract headers");
    options->extract_headers ? printf("[ON]\n") : printf("[OFF]\n");
    printf("4. Detect protocols");
    options->detect_protocols ? printf("[ON]\n") : printf("[OFF]\n");
    printf("5. Calculate statistics");
    options->calculate_statistics ? printf("[ON]\n") : printf("[OFF]\n");
    printf("6. Exit\n");
}

int main() {
    char command[MAX_COMMAND_LEN];
    CaptureOptions options = {false, false, false, false};

    printf("Packet capture program\n");

    while (1) {
        print_menu(&options);

        printf("> ");
        fgets(command, MAX_COMMAND_LEN, stdin);

        // Remove newline character from command
        command[strcspn(command, "\n")] = 0;

        if (strcmp(command, "1") == 0) {
            start_packet_capture(&options);
        } else if (strcmp(command, "2") == 0) {
            options.print_packet_info = !options.print_packet_info;
        } else if (strcmp(command, "3") == 0) {
            options.extract_headers = !options.extract_headers;
        } else if (strcmp(command, "4") == 0) {
            options.detect_protocols = !options.detect_protocols;
        } else if (strcmp(command, "5") == 0) {
            options.calculate_statistics = !options.calculate_statistics;
        } else if (strcmp(command, "6") == 0) {
            break;
        } else {
            printf("Invalid command\n");
        }
    }

    return 0;
}
