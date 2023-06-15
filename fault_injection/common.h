//
// Created by void0red on 23-6-6.
//

#ifndef AFLPLUSPLUS_COMMON_H
#define AFLPLUSPLUS_COMMON_H
#include <stdint.h>

#define MAX_FAIL_SIZE 16
#define MAX_ENABLE_SIZE 32
#define MAX_DISABLE_SIZE 128
#define FJ_SHM_ID "FJ_SHM_ID"
#define FJ_SHM_SIZE "FJ_SHM_SIZE"
#define FJ_SHM_DEFAULT_SIZE (1 << 20)

#ifdef __cplusplus
extern "C" {
#endif

/*
 * switch(on)
 * case 0: disable
 * case 1: probe
 * case 2: normal
 */
typedef struct ctl_block {
  uint32_t on;
  uint32_t hit;

  uint32_t fail_size;
  uint32_t enable_size;
  uint32_t disable_size;
  uint32_t trace_size;

  uint32_t fails[MAX_FAIL_SIZE];
  uint64_t enable_addr[MAX_ENABLE_SIZE];
  uint64_t disable_addr[MAX_DISABLE_SIZE];
  uint64_t trace_addr[0];
} __attribute__((packed)) ctl_block_t;

#ifdef __cplusplus
}
#endif

#endif  // AFLPLUSPLUS_COMMON_H
