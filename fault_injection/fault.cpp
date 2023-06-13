#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <string>
#include "fault.h"

#define INIT_FREE_SLOT 128

static ctl_block_t *init_ctl_block(uint8_t *id) {
  char name[16];
  int  len;
  len = snprintf(name, sizeof(name) - 1, "fj.%s", id);
  name[len] = 0;
  int fd = shm_open(name, O_CREAT | O_RDWR, 0666);
  if (fd < 0) {
    perror("shm_open failed");
    exit(1);
  }
  len = ftruncate(fd, CTL_BLOCK_SIZE);

  void *addr =
      mmap(nullptr, CTL_BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (addr == MAP_FAILED) {
    perror("mmap failed");
    exit(1);
  }
  close(fd);
  setenv(FAULT_INJECTION_ID_STR, name, 1);
  return static_cast<ctl_block_t *>(addr);
};

struct FailSeq {
  uint32_t              raw_hit{};
  std::vector<uint32_t> fails;
};

struct Manager {
  ctl_block_t *ctl;
  uint32_t     last_hit{};
  FailSeq     *last_seq{};

  std::deque<FailSeq *> work_queue, free_queue;

  std::function<uint8_t()> current_runner;
  std::string              current_fn;

  std::unordered_map<uint64_t, std::unordered_set<std::string>> triggered;
  std::unordered_set<std::string>                               testcases;

  explicit Manager(uint8_t *id)
      : ctl(init_ctl_block(id)), free_queue(INIT_FREE_SLOT) {
    for (int i = 0; i < INIT_FREE_SLOT; ++i) {
      free_queue.emplace_back(new FailSeq);
    }
  }

  void clear_workqueue() {
    free_queue.insert(free_queue.end(), work_queue.begin(), work_queue.end());
    work_queue.clear();
  }

  FailSeq *get_work() {
    auto *ret = work_queue.front();
    if (ret) {
      work_queue.pop_front();
      free_queue.push_back(ret);
    }
    last_seq = ret;
    return ret;
  }

  FailSeq *get_free() {
    FailSeq *ret = free_queue.front();
    if (ret) {
      free_queue.pop_front();
    } else {
      ret = new FailSeq;
    }
    work_queue.push_back(ret);
    return ret;
  }

  void clear_ctl() {
    ctl->hit = 0;
    ctl->trace_size = 0;
    ctl->fail_size = 0;
  }
  bool load_seq(FailSeq *seq) {
    ctl->on = 2;
    ctl->fail_size = seq->fails.size();
    if (ctl->fail_size > MAX_FAIL_SIZE) return false;
    for (int i = 0; i < seq->fails.size(); ++i) {
      ctl->fails[i] = seq->fails[i];
    }
    return true;
  }
  bool have_run(const std::string &fn) {
    auto pair = testcases.insert(fn);
    return !pair.second;
  }

  bool have_new_trace(const std::string &fn) {
    bool     ret = false;
    uint64_t addr;
    for (uint32_t i = 0; i < ctl->trace_size; ++i) {
      addr = ctl->trace_addr[i];
      if (!ret && triggered.find(addr) == triggered.end()) { ret = true; }
      triggered[addr].insert(fn);
    }
    return ret;
  }
};

// export to c
struct Manager *fj_init(uint8_t *id) {
  return new Manager(id);
}

ctl_block_t *fj_getctl(struct Manager *mgr) {
  return mgr->ctl;
}

init_state_t fj_init_run(struct Manager *mgr, const char *fn, fuzz_func func,
                         void *afl, void *buf, uint32_t len) {
  mgr->current_fn = fn;
  if (mgr->have_run(fn)) return FJ_INIT_SKIP;

  mgr->current_runner = [=] { return func(afl, buf, len); };

  mgr->clear_ctl();
  mgr->ctl->on = 1;

  auto ret = mgr->current_runner();
  if (ret) return FJ_INIT_ERROR;

  if (!mgr->have_new_trace(fn)) return FJ_INIT_SKIP;

  // init task
  uint32_t hit = mgr->ctl->hit;
  for (uint32_t i = 0; i < hit; ++i) {
    FailSeq *seq = mgr->get_free();
    seq->raw_hit = hit;
    seq->fails.push_back(i);
  }
  return FJ_INIT_NORMAL;
}

run_state_t fj_next_run(struct Manager *mgr) {
  mgr->clear_ctl();
  auto *seq = mgr->get_work();

  while (seq && !mgr->load_seq(seq)) {
    seq = mgr->get_work();
  }
  if (!seq) return FJ_RUN_EMPTY;

  if (mgr->current_runner()) {
    mgr->clear_workqueue();
    return FJ_RUN_ERROR;
  }
  mgr->last_hit = mgr->ctl->hit;

  if (mgr->last_hit > seq->raw_hit) {
    fj_save_current(mgr);
    // just save trigger
    mgr->have_new_trace(mgr->current_fn);
    return FJ_RUN_SAVED;
  }
  return FJ_RUN_NEXT;
}

bool fj_continue_run(struct Manager *mgr) {
  return !mgr->work_queue.empty();
}

void fj_save_current(struct Manager *mgr) {
  if (!mgr->last_seq) return;
  if (mgr->last_seq->fails.size() >= MAX_FAIL_SIZE) return;

  uint32_t              max_hit = mgr->last_hit;
  std::vector<uint32_t> fails = mgr->last_seq->fails;
  uint32_t              last_failth = *fails.end();

  for (uint32_t i = last_failth + 1; i < max_hit; ++i) {
    FailSeq *seq = mgr->get_free();
    seq->raw_hit = max_hit;
    seq->fails = fails;
    seq->fails.push_back(i);
  }
}