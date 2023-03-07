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
  ret->ctx_points = btree_create();
  ret->points = btree_create();

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
  btree_destroy(mgr->seqs_hash);
  btree_destroy(mgr->ctx_points);
  btree_destroy(mgr->points);
  free(mgr);
}

static size_t merge_sort(size_t start, size_t end, uint64_t *data,
                         uint64_t *aux) {
  if (start + 1 == end) return end;

  size_t mid = (start + end) / 2;
  size_t left_end = merge_sort(start, mid, data, aux);
  size_t right_end = merge_sort(mid, end, data, aux);

  size_t left = start;
  size_t right = mid;

  size_t i = start;
  for (; i < end; ++i) {
    if (left == left_end && right == right_end) break;
    if (left == left_end)
      aux[i] = data[right++];
    else if (right == right_end)
      aux[i] = data[left++];
    else if (data[left] < data[right])
      aux[i] = data[left++];
    else if (data[left] > data[right])
      aux[i] = data[right++];
    else if (data[left] == data[right]) {
      // dedup here
      aux[i] = data[left++];
      right += 1;
    }
  }
  for (size_t j = start; j < i; ++j) {
    data[j] = aux[j];
  }
  return i;
}

static inline void sort_enable_points(FIArea area) {
  uint32_t size = area->esize;
  if (size < 2) return;
  // do the merge sort, so we can deduplicate here
  uint64_t aux[size];
  merge_sort(0, size, area->epoint, aux);
}

static inline uint64_t calc_enable_points_hash(FIArea area) {
  sort_enable_points(area);
  return hash64((u8 *)area->epoint, area->esize * sizeof(uint64_t), 0);
}

bool CheckEnablePoint(ERManager mgr) {
  uint64_t hs = calc_enable_points_hash(mgr->area);
  return btree_insert(mgr->seqs_hash, hs);
}

btree_t CopyErrorArea(ERManager mgr) {
  btree_t ret = btree_create();
  for (uint32_t i = 0; i < mgr->area->tsize; ++i) {
    btree_insert(ret, mgr->area->tpoint[i].hash);
  }
  return ret;
}

void SetEnablePoint(ERManager mgr, const uint64_t *enables, size_t count) {
  mgr->area->esize = count;
  memcpy(mgr->area->epoint, enables, sizeof(uint64_t) * count);
  EnableFuzz(mgr);
}

bool ExistNewPoint(ERManager mgr) {
  bool exist_new = false;
  for (uint32_t i = 0; i < mgr->area->tsize; ++i) {
    EP ep = &mgr->area->tpoint[i];
    if (btree_insert(mgr->ctx_points, ep->hash)) { exist_new = true; }
    btree_insert(mgr->points, ep->id);
  }
  return exist_new;
}

void SaveEnableToTree(ERManager mgr, btree_t tree) {
  for (size_t i = 0; i < mgr->area->esize; ++i) {
    btree_insert(tree, mgr->area->epoint[i]);
  }
}

inline void EnableFuzz(ERManager mgr) {
  mgr->area->tsize = 0;
  mgr->area->stack.top = 0;
  mgr->area->enable = 1;
}

inline void DisableFuzz(ERManager mgr) {
  mgr->area->enable = 0;
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
  uint64_t buf[size];
  read(fd, buf, sizeof(buf));
  for (uint32_t i = 0; i < size; ++i) {
    btree_insert(tree, buf[i]);
  }
  close(fd);
}

void SaveEnableToFile(const uint64_t *data, size_t count, const u8 *fname) {
  if (count == 0 || !data) return;
  int fd = open(fname, O_RDWR | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
  if (fd < 0) FATAL("open %s failed\n", fname);

  ssize_t n = write(fd, &count, 4);
  if (n < 0) {
    close(fd);
    unlink(fname);
    FATAL("write %s failed\n", fname);
  }

  n = write(fd, data, sizeof(uint64_t) * count);
  if (n < 0) {
    close(fd);
    unlink(fname);
    FATAL("write %s failed\n", fname);
  }
  close(fd);
}
