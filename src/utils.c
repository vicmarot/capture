#include "utils.h"

volatile sig_atomic_t stop_capture = 0; // Global variable to track whether to stop packet capture

// Signal handler function to catch SIGINT (Ctrl+C)
void sigint_handler(int signum) {
    stop_capture = 1;
}

void reset_sigint_handler() {
    stop_capture = 0;
}
