/* Author: Vijay Nag
 * Simple and an easy to use HTTP-client
 */
#ifndef __HTTP_TIME_H__
#define __HTTP_TIME_H__

#include <time.h>
#include <sys/param.h>

typedef unsigned long long u64bits;
extern double g_TicksPerNanoSec;
extern unsigned long long start;

#define START_TICK(_start) \
  _start=RDTSC()

#define STOP_TICK(_start) \
  (RDTSC() - _start)/g_TicksPerNanoSec

static inline u64bits RDTSC()
{
  unsigned int hi, lo;
  __asm__ volatile("rdtsc" : "=a" (lo), "=d" (hi));
  return ((u64bits)hi << 32) | lo;
}

void InitRdtsc(void);
extern void test_rdtsc();
struct timespec *TimeSpecDiff(struct timespec *ts1, struct timespec *ts2);

#endif /*__HTTP_TIME_H__*/
