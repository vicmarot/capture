#ifndef UTILS_H
#define UTILS_H

#include <signal.h>

extern volatile sig_atomic_t stop_capture; // Global variable to track whether to stop packet capture


void sigint_handler(int signum);
void reset_sigint_handler();


#endif /* UTILS_H */
