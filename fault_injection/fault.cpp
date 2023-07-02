#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <string>
#include <array>
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
  len = ftruncate(fd, FJ_SHM_DEFAULT_SIZE);

  void *addr = mmap(nullptr, FJ_SHM_DEFAULT_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED, fd, 0);
  if (addr == MAP_FAILED) {
    perror("mmap failed");
    exit(1);
  }
  close(fd);
  setenv(FJ_SHM_ID, name, 1);
  return static_cast<ctl_block_t *>(addr);
};

struct FailSeq {
  std::array<uint64_t, MAX_FAIL_SIZE> data;
  size_t                              size;

  uint64_t hash() {
    uint64_t ret = 0;
    for (size_t i = 0; i < size; ++i) {
      // copy from boost hash_combine
      ret ^= data[i] + 0x9e3779b9 + (ret << 6) + (ret >> 2);
    }
  }
};

struct Manager {
  bool                         fifuzz;
  bool skip;
  std::vector<uint64_t>        new_trace;
  std::unordered_set<uint64_t> seqHash;

  ctl_block_t *ctl;
  uint32_t     last_hit{};
  FailSeq     *last_seq{};

  std::deque<FailSeq *> work_queue, free_queue;

  std::function<uint8_t()> current_runner;
  std::string              current_fn;

  std::unordered_map<uint64_t, std::unordered_set<std::string>> triggered;
  std::unordered_set<std::string>                               testcases;

  explicit Manager(uint8_t *id)
      : fifuzz(getenv("FJ_FIFUZZ") != nullptr),
      skip(getenv("FJ_SKIP") != nullptr),
        ctl(init_ctl_block(id)),
        free_queue(INIT_FREE_SLOT) {
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
    return ret;
  }

  void clear_ctl() {
    ctl->hit = 0;
    ctl->trace_size = 0;
    ctl->fail_size = 0;
  }

  void load_seq(FailSeq *seq) {
    ctl->on = 2;
    ctl->fail_size = seq->size;
    for (int i = 0; i < seq->size; ++i) {
      ctl->fail_addr[i] = seq->data[i];
    }
  }

  bool have_run(const std::string &fn) {
    auto pair = testcases.insert(fn);
    return !pair.second;
  }

  bool have_new_trace(const std::string &fn) {
    bool     ret = false;
    uint64_t addr;
    new_trace.clear();
    for (uint32_t i = 0; i < ctl->trace_size; ++i) {
      addr = ctl->trace_addr[i];
      if (triggered.find(addr) == triggered.end()) {
        ret = true;
        if (fifuzz) new_trace.push_back(addr);
      }
      triggered[addr].insert(fn);
    }
    return ret;
  }

  init_state_t init_task() {
    if (have_run(current_fn)) return FJ_INIT_SKIP;

    clear_ctl();
    ctl->on = 1;

    auto ret = current_runner();
    if (ret) return FJ_INIT_ERROR;

    if (!have_new_trace(current_fn)) return FJ_INIT_SKIP;

    // init task
    if (fifuzz) {
      for (auto v : new_trace) {
        FailSeq *seq = get_free();
        seq->size = 1;
        seq->data[0] = v;
        work_queue.push_back(seq);
      }
    } else {
      uint32_t hit = ctl->hit;
      for (uint32_t i = 1; i <= hit; ++i) {
        FailSeq *seq = get_free();
        seq->size = 1;
        seq->data[0] = i;
        work_queue.push_back(seq);
      }
    }
    return FJ_INIT_NORMAL;
  }

  run_state_t run_next() {
    clear_ctl();
    auto *seq = get_work();
    if (!seq) return FJ_RUN_EMPTY;

    if (current_runner()) {
      clear_workqueue();
      return FJ_RUN_ERROR;
    }
    last_hit = ctl->hit;

    if (have_new_trace(current_fn)) {
      create_new_work();
      return FJ_RUN_SAVED;
    }
    return FJ_RUN_NEXT;
  }

  bool seq_check(FailSeq *seq) {
    if (seq->size == 0) return false;
    auto pair = seqHash.insert(seq->hash());
    return pair.second;
  }

  inline void fifuzz_save() {
    auto data = last_seq->data;
    auto size = last_seq->size;
    // if we need hash the seq to dedup?
    for (auto i : new_trace) {
      FailSeq *seq = get_free();
      seq->size = size + 1;
      seq->data[size + 1] = i;
      if (seq_check(seq))
        work_queue.push_back(seq);
      else
        free_queue.push_back(seq);
    }
  }

  inline void normal_save() {
    auto     data = last_seq->data;
    auto     size = last_seq->size;
    uint32_t max_hit = last_hit;

    for (uint32_t i = data[size] + 1; i <= max_hit; ++i) {
      FailSeq *seq = get_free();
      seq->size = size + 1;
      seq->data[size + 1] = i;
      work_queue.push_back(seq);
    }
  }

  void create_new_work() {
    if (!last_seq || skip) return;
    auto size = last_seq->size;
    if (size == MAX_FAIL_SIZE) return;

    if (fifuzz) {
      fifuzz_save();
    } else {
      normal_save();
    }
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
  mgr->current_runner = [=] { return func(afl, buf, len); };
  return mgr->init_task();
}

run_state_t fj_next_run(struct Manager *mgr) {
  return mgr->run_next();
}

bool fj_continue_run(struct Manager *mgr) {
  return !mgr->work_queue.empty();
}

void fj_save_current(struct Manager *mgr) {
  mgr->create_new_work();
}

bool check_randomize() {
  if (getenv(FJ_DISABLE_RANDOMIZE_CHECK)) return true;
  int fd = open("/proc/sys/kernel/randomize_va_space", O_RDONLY);
  if (fd < 0) return false;
  char buf[2];
  if (read(fd, buf, sizeof(buf)) < 0) {
    close(fd);
    return false;
  }
  close(fd);
  if (buf[0] != '0') return false;
  return true;
}