#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <pthread.h>
#include "include/cpu.h"

#define CPU_CORE 16
void pin_to_cpu(int cpu) {
	cpu_set_t cpuset;	// set of CPUs allocating to the LVRM

    /*
	if (getuid()) {
        // exit if user is not root
        LOG_ERR("Root required\n");
		return;
	}
    */

	CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) < 0) {
        fprintf(stderr, "set thread affinity failed\n");
    }
    cpu_set_t get;
    CPU_ZERO(&get);
    if (pthread_getaffinity_np(pthread_self(), sizeof(get), &get) < 0) {
        fprintf(stderr, "get thread affinity failed\n");
    }
    /*
    for (int j = 0; j < CPU_CORE; j++) {
        if (CPU_ISSET(j, &get)) {
            fprintf(stderr, "    running in processor %d\n", j);
        }
    }
    */
}

int pin_array[15] = {
    0,
    4,
    1,
    5,
    2,
    6,
    3,
    7
};

void pin_thread(int id) {
    pin_to_cpu(pin_array[id]);
}
