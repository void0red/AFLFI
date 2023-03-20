//
// Created by void0red on 23-2-28.
//
#include "fault_injection.h"
#include <fcntl.h>
#include <malloc.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void *mk_shm(const char *name, int size) {
  int fd = shm_open(name, O_CREAT | O_RDWR, 0666);
  if (fd < 0) PFATAL("shm_open failed");

  ftruncate(fd, size);
  void *ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (ret == MAP_FAILED) PFATAL("mmap failed");
  memset(ret, 0, size);
  return ret;
}

ERManager NewERManager(const char *name) {
  ERManager ret = calloc(1, sizeof(struct error_manager));
  if (ret == NULL) PFATAL("malloc failed");

  ret->seqs_hash = btree_create();
  ret->one_enable = btree_create();
  ret->trace_aux = malloc(DEFAULT_TRACE_AUX_SIZE * sizeof(uint32_t));
  if (ret->trace_aux == NULL) PFATAL("malloc failed");
  ret->trace_aux_capacity = DEFAULT_TRACE_AUX_SIZE;

  char buf[16];
  int  len;
  len = snprintf(buf, sizeof(buf) - 1, "fj.%s", name);
  buf[len] = 0;
  ret->area = mk_shm(buf, sizeof(struct fault_injection_area));

  setenv(FAULT_INJECTION_ID_STR, buf, 1);

  return ret;
}

void FreeERManager(ERManager mgr) {
  munmap(mgr->area, sizeof(struct fault_injection_area));
  free(mgr->trace_aux);
  btree_destroy(mgr->one_enable);
  btree_destroy(mgr->seqs_hash);
  free(mgr);
}

static size_t do_merge_sort(uint32_t *data, size_t begin, size_t end) {
  static uint32_t tmp[DEFAULT_TRACE_AUX_SIZE];
  if (begin + 1 == end) return end;
  size_t mid = (begin + end) / 2;
  size_t left_end = do_merge_sort(data, begin, mid);
  size_t right_end = do_merge_sort(data, mid, end);

  size_t left = begin;
  size_t right = mid;

  size_t i = begin;
  for (; i < end; ++i) {
    if (left == left_end && right == right_end) break;
    if (left == left_end)
      tmp[i] = data[right++];
    else if (right == right_end)
      tmp[i] = data[left++];
    else if (data[left] < data[right])
      tmp[i] = data[left++];
    else if (data[left] > data[right])
      tmp[i] = data[right++];
    else if (data[left] == data[right]) {
      // dedup here
      tmp[i] = data[left++];
      right += 1;
    }
  }
  for (size_t j = begin; j < i; ++j) {
    data[j] = tmp[j];
  }
  return i;
}

bool CheckIfDupEnables(ERManager mgr, uint32_t *enables, size_t count) {
#ifdef FJ_ENABLE_DEDUP
  static uint32_t sorted_enables[DEFAULT_TRACE_AUX_SIZE];
  if (count == 0) return false;
  if (count == 1) return btree_insert(mgr->one_enable, enables[0]);
  // sort and dedup here
  memcpy(sorted_enables, enables, sizeof(uint32_t) * count);
  size_t new_count = do_merge_sort(sorted_enables, 0, count);
  if (new_count == 1) return btree_insert(mgr->one_enable, sorted_enables[0]);
  return btree_insert(mgr->seqs_hash, hash32((u8 *)sorted_enables,
                                             sizeof(uint32_t) * new_count, 0));
#else
  return true;
#endif
}

void SetEnablePoint(ERManager mgr, uint32_t *enables, size_t count) {
  memset(mgr->area->enables, 0, sizeof(mgr->area->enables));
  // !! must use 64bit here
  uint64_t idx;
  for (size_t i = 0; i < count; ++i) {
    idx = enables[i];
    mgr->area->enables[idx >> 6] |= 1 << (idx & 63);
  }
  memset(mgr->area->trace, 0, sizeof(mgr->area->trace));
  mgr->current_enables = enables;
  mgr->current_enables_count = count;
}

static inline void trace_aux_push(ERManager mgr, uint32_t val) {
  if (unlikely(mgr->trace_aux_count >= mgr->trace_aux_capacity)) {
    mgr->trace_aux_capacity *= 2;
    mgr->trace_aux =
        realloc(mgr->trace_aux, mgr->trace_aux_capacity * sizeof(uint32_t));
  }
  mgr->trace_aux[mgr->trace_aux_count++] = val;
}

void SnapshotTraceAndEnable(ERManager mgr) {
  mgr->trace_aux_count = 0;
  mgr->enables_aux_count = 0;

  uint64_t *trace = mgr->area->trace;
  uint32_t  val;
  for (size_t i = 0; i < MAX_TRACE; ++i) {
    if (!trace[i]) continue;
    val = i << 6;
    for (uint32_t n = 0; n < 64; ++n) {
      if (trace[i] & (1 << n)) trace_aux_push(mgr, val + n);
    }
  }
  if (unlikely(mgr->current_enables_count >= DEFAULT_TRACE_AUX_SIZE))
    FATAL("what a large enables count");
  mgr->enables_aux_count = mgr->current_enables_count;
  memcpy(mgr->enables_aux, mgr->current_enables,
         sizeof(uint32_t) * mgr->current_enables_count);
}

static inline uint32_t count_bits(uint64_t i) {
  i = i - ((i >> 1) & 0x5555555555555555);
  i = (i & 0x3333333333333333) + ((i >> 2) & 0x3333333333333333);
  return (((i + (i >> 4)) & 0xF0F0F0F0F0F0F0F) * 0x101010101010101) >> 56;
}

bool CheckIfExistNewPoint(ERManager mgr) {
  if (mgr->cur_depth >= MAX_FJ_DEPTH) return false;
  bool      exist_new = false;
  uint64_t *trace = mgr->area->trace;
  uint64_t  res;
  for (size_t i = 0; i < MAX_TRACE; ++i) {
    if (!trace[i]) continue;
    /*
     * we should find 0 -> 1 case
     * 0,0 -> 0
     * 0,1 -> 1
     * 1,0 -> 0
     * 1,1 -> 0
     * ~a*b
     */
    res = ~(mgr->points[i]) & trace[i];
    if (res) {
      exist_new = true;
      mgr->points_count += count_bits(res);
      mgr->points[i] |= trace[i];
    }
  }
  return exist_new;
}

void SaveEnableToTree(ERManager mgr, btree_t tree) {
  for (size_t i = 0; i < mgr->current_enables_count; ++i) {
    btree_insert(tree, mgr->current_enables[i]);
  }
}

void LoadEnableFromFile(btree_t tree, const u8 *fname) {
  int fd = open(fname, O_RDONLY);
  if (fd < 0) return;
  uint32_t size = 0;
  ssize_t  n = read(fd, &size, sizeof(size));
  if (n < 0 || size == 0) {
    close(fd);
    return;
  }
  uint32_t buf[size];
  read(fd, buf, sizeof(buf));
  for (uint32_t i = 0; i < size; ++i) {
    btree_insert(tree, buf[i]);
  }
  close(fd);
}

void SaveEnableToFile(const uint32_t *data, size_t count, const u8 *fname) {
  if (count == 0 || !data) return;
  int fd = open(fname, O_RDWR | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
  if (fd < 0) FATAL("open %s failed\n", fname);

  ssize_t n = write(fd, &count, 4);
  if (n < 0) {
    close(fd);
    unlink(fname);
    FATAL("write %s failed\n", fname);
  }

  n = write(fd, data, sizeof(uint32_t) * count);
  if (n < 0) {
    close(fd);
    unlink(fname);
    FATAL("write %s failed\n", fname);
  }
  close(fd);
}
