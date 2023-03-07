#ifndef __FAULT_INJECTION_H
#define __FAULT_INJECTION_H
#include <stdbool.h>
#include <stdint.h>
#include "debug.h"
#include "hash.h"
#include "btree.h"

#define MAX_ENABLE_POINT 32
#define MAX_STACK_SIZE 512
// 4k errors may be enough
#define MAX_ERRORS_N 12
#define MAX_ERRORS (1 << MAX_ERRORS_N)
#define MAX_ERRORS_BITMASK (MAX_ERRORS-1)
#define DEFAULT_BUCKET (MAX_ERRORS * 10)
#define FAULT_INJECTION_ID_STR "__FAULT_INJECTION_ID"

enum TraceType {
  FuncEntry = 0xE0,
  FuncExit = 0xE1,
  CallEntry = 0xE2,
  CallExit = 0xE3,
  ErrorCollect = 0xE4,
  ErrorBranch = 0xE5,
};
#define TRACE_PREFIX_SHIFT (64 - 8)

/*
 * the point can inject fault
 * @id    label as identity, consist of trace type(8bit) filehash(16bit)
 *        funchash(16bit) counter(24bit)
 * @parm  hash: context hash
 */
struct error_point {
  uint64_t id;
  uint64_t hash;
};
typedef struct error_point *EP;

/*
 * emulate stack for calc context hash
 * @top   top idx of the stack
 * @data  real data in stack
 */
struct emu_stack {
  int      top;
  uint64_t data[MAX_STACK_SIZE];
};
typedef struct emu_stack *Stack;

/*
 * in shared memory struct
 * @tsize     size of triggered points
 * @tpoint    triggered points
 * @esize     size of enabled points
 * @epoint    enabled points
 */
struct fault_injection_area {
  uint32_t           enable;
  uint32_t           tsize;
  struct error_point tpoint[MAX_ERRORS];
  uint32_t           esize;
  uint64_t           epoint[MAX_ENABLE_POINT];
  struct emu_stack   stack;
};
typedef struct fault_injection_area *FIArea;

struct error_manager {
  btree_t seqs_hash;
  btree_t ctx_points;
  btree_t points;
  FIArea  area;
};

typedef struct error_manager *ERManager;

ERManager NewERManager(const char *name);
void      FreeERManager(ERManager mgr);
btree_t   CopyErrorArea(ERManager mgr);
bool      CheckEnablePoint(ERManager mgr);
void      EnableFuzz(ERManager mgr);
void      DisableFuzz(ERManager mgr);
void      SetEnablePoint(ERManager mgr, const uint64_t *enables, size_t count);
bool      ExistNewPoint(ERManager mgr);
void      SaveEnableToTree(ERManager mgr, btree_t tree);
void      LoadEnableFromFile(btree_t tree, const u8 *fname);
void      SaveEnableToFile(const uint64_t *data, size_t count, const u8 *fname);
#endif  // __FAULT_INJECTION_H