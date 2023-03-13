//
// Created by void0red on 23-3-1.
//

#ifndef AFLPLUSPLUS_BTREE_H
#define AFLPLUSPLUS_BTREE_H
#include <stdint.h>
#include <stdbool.h>
#include "debug.h"
#include <stdio.h>
#include "rbtree.h"

typedef struct _btree_node {
  uint32_t       value;
  struct rb_node node;
} btree_node_t, *btree_node_p;

typedef struct {
  size_t         size;
  struct rb_root root;

  uint32_t *values;
  size_t    capacity;
} *btree_t;

btree_t btree_create();
void    btree_destroy(btree_t tree);
// insert value, return true if success, return false if exist.
bool btree_insert(btree_t tree, uint32_t value);

#endif  // AFLPLUSPLUS_BTREE_H
