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
#include <threads.h>

#define XXH_INLINE_ALL
#include "../include/xxhash.h"
#undef XXH_INLINE_ALL

static struct ctl_block *cb;
static bool              __init_done = false;
static bool              __afl_debug = false;
static size_t            shm_size = FJ_SHM_DEFAULT_SIZE;
static bool              have_fault = false;
static bool              no_ctx = false;

__attribute__((destructor)) void __fault_injection_finit() {
  if (!__init_done || !cb) return;
  cb->on = 0;
}

__attribute__((constructor(10086))) void __fault_injection_init() {
  if (__init_done) return;
  if (getenv("AFL_DEBUG")) __afl_debug = true;
  no_ctx = getenv("FJ_NO_CTX") != NULL;

  char *id = getenv(FJ_SHM_ID);
  if (!id || id[0] == '\0') {
    if (__afl_debug) fprintf(stderr, "can't find FJ_SHM_ID env\n");
    return;
  }
  char *size = getenv(FJ_SHM_SIZE);
  if (size) {
    size_t new_size = strtoll(size, NULL, 10);
    if (new_size > shm_size) shm_size = new_size;
  }

  int fd = shm_open(id, O_RDWR, 0666);
  if (fd < 0) {
    if (__afl_debug) fprintf(stderr, "shm_open failed\n");
    return;
  }

  cb = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (cb == MAP_FAILED) {
    if (__afl_debug) fprintf(stderr, "mmap failed\n");
    return;
  }

  if (__afl_debug)
    fprintf(stderr, "fault injection control block at %p, size %ld\n", cb,
            shm_size);

  __init_done = true;
}

#define STACK_BUFFER_SIZE 64
thread_local void *stack_buf[STACK_BUFFER_SIZE] = {NULL};

static inline void print_stack(uint64_t addr) {
  fprintf(stderr, "failth %d, addr 0x%lx\n", cb->hit, addr);
  int stack_buf_len = backtrace(stack_buf, STACK_BUFFER_SIZE);
  if (stack_buf_len > 0) {
    char **sym = backtrace_symbols(stack_buf, stack_buf_len);
    for (int i = 0; i < stack_buf_len; ++i) {
      fprintf(stderr, "%p,%s\n", stack_buf[i], sym[i]);
    }
    free(sym);
  }
}

static inline void do_log(uint64_t addr) {
  uint64_t *slot = &cb->trace_addr[cb->trace_size];
  if ((void *)slot >= (void *)cb + shm_size) {
    fprintf(stderr, "full track buffer\n");
    return;
  }
  if (no_ctx) {
    *slot = addr;
    cb->trace_size += 1;
  } else {
    int stack_buf_len = backtrace(stack_buf, STACK_BUFFER_SIZE);
    if (stack_buf_len <= 0) return;
    uint64_t v = XXH3_64bits(stack_buf, stack_buf_len * sizeof(void *));
    *slot = v;
    cb->trace_size += 1;
  }
}

bool __fault_injection_control() {
  if (!__init_done || !cb->on) return false;
  uint64_t addr = (uint64_t)__builtin_return_address(0);
  cb->hit++;
  if (cb->on == 1) {
    do_log(addr);
    return false;
  }

  if (have_fault) do_log(addr);

  for (uint32_t i = 0; i < cb->disable_size; ++i) {
    if (addr == cb->disable_addr[i]) return false;
  }

  for (uint32_t i = 0; i < cb->enable_size; ++i) {
    if (addr == cb->enable_addr[i]) {
      have_fault = true;
      if (__afl_debug) print_stack(addr);
      return true;
    }
  }

  for (uint32_t i = 0; i < cb->fail_size; ++i) {
    if (cb->hit == cb->fail_addr[i]) {
      have_fault = true;
      if (__afl_debug) print_stack(addr);
      return true;
    }
  }
  return false;
}
