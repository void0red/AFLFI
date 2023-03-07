//
// Created by void0red on 23-3-1.
//

#ifndef AFLPLUSPLUS_BTREE_H
#define AFLPLUSPLUS_BTREE_H
#include <stdint.h>
#include <stdbool.h>
#include "debug.h"
#include <stdio.h>

typedef struct _btree_node {
  uint64_t            value;
  struct _btree_node *left, *right;
} btree_node_t, *btree_node_p;

typedef struct {
  size_t       size;
  btree_node_p root;

  uint64_t *values;
  size_t    capacity;
} *btree_t;

btree_t btree_create();
void    btree_destroy(btree_t tree);
// search for target
bool btree_search(btree_t tree, uint64_t target);
// insert value, return true if success, return false if exist.
bool btree_insert(btree_t tree, uint64_t value);

#endif  // AFLPLUSPLUS_BTREE_H
