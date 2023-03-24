#ifndef __FAULT_INJECTION_H
#define __FAULT_INJECTION_H
#include <stdbool.h>
#include <stdint.h>
#include "debug.h"
#include "hash.h"
#include "btree.h"

#define MAX_TRACE (1 << 14)
#define MAX_TRACE_BITS (MAX_TRACE << 6)
#define FAULT_INJECTION_ID_STR "__FAULT_INJECTION_ID"
#define MAX_FJ_DEPTH 3
#define FJ_ENABLE_DEDUP
typedef struct fault_injection_area {
  uint64_t status;
  uint32_t distance_count;
  uint32_t distance;
  uint64_t trace[MAX_TRACE];
  uint64_t enables[MAX_TRACE];
} __attribute__((packed)) * FIArea;

struct error_manager {
  btree_t  seqs_hash;
  btree_t  one_enable;
  uint64_t points[MAX_TRACE];
  uint32_t points_count;
  u8       cur_depth;
  double   min_distance;
  double   max_distance;

  // current_enables don't hold the memory
  uint32_t *current_enables;
  size_t    current_enables_count;

  uint32_t *trace_aux;
#define DEFAULT_TRACE_AUX_SIZE 2048
  size_t trace_aux_count, trace_aux_capacity;
#define DEFAULT_ENABLES_AUX_SIZE 32
  uint32_t enables_aux[DEFAULT_ENABLES_AUX_SIZE];
  uint32_t enables_aux_count;

  FIArea area;
};

typedef struct error_manager *ERManager;

ERManager NewERManager(const char *name);
void      FreeERManager(ERManager mgr);
void      SnapshotTraceAndEnable(ERManager mgr);
// return true if success, return false if dup
bool CheckIfDupEnables(ERManager mgr, uint32_t *enables, size_t count);
void SetEnablePoint(ERManager mgr, uint32_t *enables, size_t count);
bool CheckIfExistNewPoint(ERManager mgr);
void SaveEnableToTree(ERManager mgr, btree_t tree);
void LoadEnableFromFile(btree_t tree, const u8 *fname);
void SaveEnableToFile(const uint32_t *data, size_t count, const u8 *fname);

double CalcDistance(ERManager mgr);
#endif  // __FAULT_INJECTION_H