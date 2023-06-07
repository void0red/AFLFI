//
// Created by void0red on 23-6-6.
//

#ifndef AFLPLUSPLUS_COMMON_H
#define AFLPLUSPLUS_COMMON_H
#include <stdint.h>

#define MAX_ENABLE_SIZE 32
#define MAX_FAIL_SIZE 16

struct ctl_block {
  uint32_t enable;
  uint32_t hit;
  uint32_t log_lvl;
  int32_t debug_fd;

  uint32_t fail_size;
  uint32_t enable_size;
  uint32_t disable_size;

  uint32_t fails[MAX_FAIL_SIZE];
  uint64_t enable_addr[MAX_ENABLE_SIZE];
  uint64_t disable_addr[0];
} __attribute__((packed));

#define CTL_BLOCK_SIZE (4096)
#define FAULT_INJECTION_ID_STR "__fault_injection_id"

#endif  // AFLPLUSPLUS_COMMON_H
