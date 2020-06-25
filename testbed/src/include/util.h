#ifndef __OMNIMON_UTIL_H__
#define __OMNIMON_UTIL_H__

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sched.h>
#include <assert.h>

#define MB (1024*1024)
#define GB (1024*1024*1024)

#define likely(x) __builtin_expect ((x), 1)
#define unlikely(x) __builtin_expect ((x), 0)

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

// #define DEBUG


#define afs_assert(x, ...) \
    do {\
        if (afs_unlikely(!(x))) {\
            fprintf (stderr, "Assertion failed at %s (%s:%d): ", #x, \
                __FILE__, __LINE__);\
            fprintf (stderr, "" __VA_ARGS__);\
            fflush(stderr);\
            exit(EXIT_FAILURE);\
        }\
    } while (0) 

#define LOG_MSG(...) \
    do { \
        fprintf(stdout, __VA_ARGS__); \
        fflush(stdout);\
    } while (0)
#define LOG_WARN(...) \
    do { \
        fprintf(stderr, "[WARN] " __VA_ARGS__); \
        fflush(stderr);\
    } while(0)
#define LOG_ERR(...) \
    do { \
        fprintf(stderr, "[ERROR] "  __VA_ARGS__); \
        exit(EXIT_FAILURE); \
    } while (0)

#ifdef DEBUG
#define LOG_DEBUG(...) \
    do { \
        fprintf(stderr, "[DEBUG]" __VA_ARGS__); \
        fflush(stderr); \
    } while (0)
#else
#define LOG_DEBUG(...)
#endif

static inline uint64_t now_us ()
{
    //  Use POSIX gettimeofday function to get precise time.
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (tv.tv_sec * (uint64_t) 1000000 + tv.tv_usec);
}

static inline void *stopwatch_start ()
{
    uint64_t *watch = (uint64_t*) malloc (sizeof (uint64_t));
    *watch = now_us ();
    return (void*) watch;
}

static inline unsigned long stopwatch_stop (void *watch_)
{
    uint64_t end = now_us ();
    uint64_t start = *(uint64_t*) watch_;
    free (watch_);
    return (unsigned long) (end - start);
}

int cmp (const void * a, const void * b);
int cmp_lf (const void * a, const void * b);
int cmp_ll (const void * a, const void * b);
int cmp_int32 (const void * a, const void * b);
int cmp_size (const void * a, const void * b);

void quitmemory(void * pointer);
long long ll_abs(long long a);

//#define CPU_CORE 16
//static void pin_to_cpu(int cpu) {
//	cpu_set_t cpuset;	// set of CPUs allocating to the LVRM
//
//    /*
//	if (getuid()) {
//        // exit if user is not root
//        LOG_ERR("Root required\n");
//		return;
//	}
//    */
//
//	CPU_ZERO(&cpuset);
//    CPU_SET(cpu, &cpuset);
//    if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) < 0) {
//        fprintf(stderr, "set thread affinity failed\n");
//    }
//    cpu_set_t get;
//    CPU_ZERO(&get);
//    if (pthread_getaffinity_np(pthread_self(), sizeof(get), &get) < 0) {
//        fprintf(stderr, "get thread affinity failed\n");
//    }
//    for (int j = 0; j < CPU_CORE; j++) {
//        if (CPU_ISSET(j, &get)) {
//            LOG_MSG("    running in processor %d\n", j);
//        }
//    }
//}

#endif // __OMNIMON_UTIL_H_
