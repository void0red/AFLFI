//
// Created by void0red on 23-6-6.
//
#include "common.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <execinfo.h>
static struct ctl_block *cb;
static FILE             *debug_stream;
static uint32_t          failth = 0;
static bool              __init_done = false;
static bool              __afl_debug = false;

__attribute__((constructor(10086))) void __fault_injection_init() {
  if (__init_done) return;
  if (getenv("AFL_DEBUG")) __afl_debug = true;

  char *id = getenv(FAULT_INJECTION_ID_STR);
  if (!id || id[0] == '\0') {
    if (__afl_debug) fprintf(stderr, "can't find FAULT_INJECTION_ID_STR env");
    return;
  }
  int fd = shm_open(id, O_RDWR, 0666);
  if (fd < 0) {
    if (__afl_debug) fprintf(stderr, "shm_open failed\n");
    return;
  }

  cb = mmap(NULL, CTL_BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (cb == MAP_FAILED) {
    if (__afl_debug) fprintf(stderr, "mmap failed\n");
    return;
  }

  if (__afl_debug) fprintf(stderr, "fault injection control block at %p\n", cb);

  if (cb->log_lvl) {
    debug_stream = fdopen(cb->debug_fd, "w+");
    if (!debug_stream) {
      if (__afl_debug) fprintf(stderr, "open debug file failed\n");
    }
  }

  __init_done = true;
}

static inline void do_log(uint64_t addr) {
  if (!debug_stream) return;
  fprintf(debug_stream, "failth %d, addr 0x%lx\n", failth, addr);

  if (cb->log_lvl > 1) {
#define STACK_BUFFER_SIZE 128
    void *buf[STACK_BUFFER_SIZE] = {NULL};
    int   size = backtrace(buf, STACK_BUFFER_SIZE);
    if (size > 0) {
      fflush(debug_stream);
      backtrace_symbols_fd(buf, size, cb->debug_fd);
      fprintf(debug_stream, "\n\n");
    }
  }
}

bool __fault_injection_control() {
  if (!__init_done) return false;
  uint64_t addr = (uint64_t)__builtin_return_address(0);
  cb->hit++;
  for (uint32_t i = 0; i < cb->disable_size; ++i) {
    if (addr == cb->disable_addr[i]) return false;
  }

  for (uint32_t i = 0; i < cb->enable_size; ++i) {
    if (addr == cb->enable_addr[i]) {
      do_log(addr);
      return true;
    }
  }

  failth += 1;
  for (uint32_t i = 0; i < cb->fail_size; ++i) {
    if (failth == cb->fails[i]) {
      do_log(addr);
      return true;
    }
  }

  return false;
}
