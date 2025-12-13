#ifndef TIMING_H
#define TIMING_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <time.h>

typedef struct {
    long long QuadPart;
} LARGE_INTEGER;

static inline void QueryPerformanceFrequency(LARGE_INTEGER* frequency) {
    if (!frequency) {
        return;
    }
    frequency->QuadPart = 1000000000LL; // nanoseconds per second
}

static inline void QueryPerformanceCounter(LARGE_INTEGER* counter) {
    if (!counter) {
        return;
    }
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    counter->QuadPart = ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

#endif // TIMING_H
