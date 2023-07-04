//
// Created by void0red on 23-6-20.
//

#include "common.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <execinfo.h>

#define XXH_INLINE_ALL
#include "../include/xxhash.h"
#undef XXH_INLINE_ALL

static struct ctl_block *cb;
static bool              __init_done = false;
static bool              __afl_debug = false;
static size_t            shm_size = FJ_SHM_DEFAULT_SIZE;

__attribute__((destructor)) void __fault_injection_finit() {
  if (!__init_done || !cb) return;
  cb->on = 0;
}

__attribute__((constructor(10086))) void __fault_injection_init() {
  if (__init_done) return;
  if (getenv("AFL_DEBUG")) __afl_debug = true;

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

enum TraceType {
  FuncEntry = 0xE0,
  FuncExit = 0xE1,
  CallEntry = 0xE2,
  CallExit = 0xE3,
  ErrorCollect = 0xE4,
};
#define TRACE_PREFIX_SHIFT (64 - 8)
struct emu_stack {
  int      top;
  uint64_t data[STACK_BUFFER_SIZE];
};

static struct emu_stack stack_;

static inline void emu_stack_push(struct emu_stack *stack, uint64_t value) {
  if (stack->top == STACK_BUFFER_SIZE) {
    fprintf(stderr, "emu stack full\n");
    return;
  }
  stack->data[stack->top++] = value;
}

static inline bool emu_stack_pop_until(struct emu_stack *stack,
                                       uint64_t          expect) {
  if (stack->top == 0) return false;

  while (--stack->top >= 0) {
    if (stack->data[stack->top] == expect) return true;
  }
  stack->top = 0;
  return false;
}

static inline uint64_t to_expect(uint8_t prefix, uint64_t value) {
  return ((uint64_t)prefix << TRACE_PREFIX_SHIFT) |
         (value & ((1UL << TRACE_PREFIX_SHIFT) - 1));
}

void *stack_buf[STACK_BUFFER_SIZE] = {NULL};

static inline uint64_t emu_hash(struct emu_stack *stack, uint64_t id) {
  int size = backtrace(stack_buf, STACK_BUFFER_SIZE);
  if (size <= 0) { exit(-1); }
  return XXH3_64bits(stack_buf, size * sizeof(void *));
}

void __fault_injection_trace(uint64_t id) {
  if (!__init_done || !cb->on) return;

  uint8_t prefix = id >> TRACE_PREFIX_SHIFT;
  switch (prefix) {
    case FuncEntry:
    case CallEntry: {
      emu_stack_push(&stack_, id);
      break;
    }
    case FuncExit: {
      emu_stack_pop_until(&stack_, to_expect(FuncEntry, id));
      break;
    }
    case CallExit: {
      emu_stack_pop_until(&stack_, to_expect(CallEntry, id));
      break;
    }
    case ErrorCollect: {
      // collect in control
      //      cb->trace_addr[cb->trace_size++] = emu_hash(&stack_, id);
      break;
    }
    default:
      fprintf(stderr, "trace data corruption\n");
  }
}

bool __fault_injection_control(uint64_t id) {
  if (!__init_done || !cb->on) return false;
  cb->hit += 1;
  uint64_t hs = emu_hash(&stack_, id);
  cb->trace_addr[cb->trace_size++] = hs;
  bool ret = false;
  for (uint32_t i = 0; i < cb->fail_size; ++i) {
    if (cb->fail_addr[i] == hs) {
      ret = true;
      break;
    }
  }
//  if (__afl_debug && ret) fprintf(stderr, "fj control 0x%lx\n", id);
  return ret;
}
