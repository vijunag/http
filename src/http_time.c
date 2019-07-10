/* Author: Vijay Nag
 * Simple and an easy to use HTTP-client
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <http_time.h>

const int NANO_SECONDS_IN_SEC = 1000000000;
/* returns a static buffer of struct timespec with the time difference of ts1 and ts2
   ts1 is assumed to be greater than ts2 */
struct timespec *TimeSpecDiff(struct timespec *ts1, struct timespec *ts2)
{
  static struct timespec ts;
  ts.tv_sec = ts1->tv_sec - ts2->tv_sec;
  ts.tv_nsec = ts1->tv_nsec - ts2->tv_nsec;
  if (ts.tv_nsec < 0) {
    ts.tv_sec--;
    ts.tv_nsec += NANO_SECONDS_IN_SEC;
  }
  return &ts;
}

double g_TicksPerNanoSec;
static void CalibrateTicks()
{
  struct timespec begints, endts;
  u64bits begin = 0, end = 0;
  clock_gettime(CLOCK_MONOTONIC, &begints);
  begin = RDTSC();
  u64bits i;
  for (i = 0; i < 1000000; i++); /* must be CPU intensive */
  end = RDTSC();
  clock_gettime(CLOCK_MONOTONIC, &endts);
  struct timespec *tmpts = TimeSpecDiff(&endts, &begints);
  u64bits nsecElapsed = tmpts->tv_sec * 1000000000LL + tmpts->tv_nsec;
  g_TicksPerNanoSec = (double)(end - begin)/(double)nsecElapsed;
}

/* Call once before using RDTSC, has side effect of binding process to CPU1 */
void InitRdtsc(void)
{
  int rval;
  unsigned long cpuMask;
  cpuMask = 1; // bind to cpu 1
  rval=sched_setaffinity(0, sizeof(cpuMask), &cpuMask);
  if (rval < 0)
    printf("sched_setaffinity() failed with errno:%s\n",strerror(errno));
  CalibrateTicks();
}

void test_rdtsc(void)
{
  u64bits s,e;

  START_TICK(s);
  poll(NULL,0,1000); //poll for a sec and check if ticks return a second
  e=STOP_TICK(s);
  printf("%.2f seconds\n",e/1000000000.0);
}
