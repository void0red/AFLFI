#ifndef AFLPLUSPLUS_FAULT_H
#define AFLPLUSPLUS_FAULT_H
#ifdef __cplusplus
extern "C" {
#endif
#include "../fault_injection/common.h"

struct FailSeq;
struct Manager;
struct Manager *fj_init(uint8_t *id);
ctl_block_t    *fj_getctl(struct Manager *mgr);

typedef uint8_t (*fuzz_func)(void *, void *, uint32_t);

typedef enum init_state {
  FJ_INIT_NORMAL,
  FJ_INIT_SKIP,
  FJ_INIT_ERROR
} init_state_t;

init_state_t fj_init_run(struct Manager *mgr, const char *fn, fuzz_func func,
                         void *afl, void *buf, uint32_t len);

bool fj_continue_run(struct Manager *mgr);
void fj_save_current(struct Manager *mgr);

typedef enum run_state {
  FJ_RUN_NEXT,
  FJ_RUN_SAVED,
  FJ_RUN_EMPTY,
  FJ_RUN_ERROR,
} run_state_t;

run_state_t fj_next_run(struct Manager *mgr);

#define FJ_DISABLE_RANDOMIZE_CHECK "FJ_DISABLE_RANDOMIZE_CHECK"
bool check_randomize();
#ifdef __cplusplus
}
#endif
#endif  // AFLPLUSPLUS_FAULT_H