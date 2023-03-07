//
// Created by void0red on 23-3-1.
//
#include "btree.h"

static inline size_t capacity_grow(size_t old) {
  return 2 * old;
}

static inline btree_node_p btree_node_alloc(btree_t tree, uint64_t val) {
  btree_node_p node = calloc(1, sizeof(*node));
  if (unlikely(!node)) FATAL("calloc failed");
  node->value = val;
  tree->size += 1;
  if (tree->size > tree->capacity) {
    tree->capacity = capacity_grow(tree->capacity);
    tree->values = realloc(tree->values, sizeof(uint64_t) * tree->capacity);
  }
  tree->values[tree->size - 1] = val;
  return node;
}

btree_t btree_create() {
  btree_t ret = calloc(1, sizeof(*ret));
  if (unlikely(!ret)) FATAL("calloc failed");
  ret->capacity = 1;
  ret->values = malloc(sizeof(uint64_t));
  return ret;
}
static void btree_node_free(btree_node_p node) {
  if (!node) return;
  btree_node_free(node->left);
  node->left = NULL;
  btree_node_free(node->right);
  node->right = NULL;
  free(node);
}

void btree_destroy(btree_t tree) {
  btree_node_free(tree->root);
  free(tree->values);
  free(tree);
}

static inline btree_node_p search_node(btree_node_p node, uint64_t value) {
  btree_node_p pos = node;
  btree_node_p ppos = node;
  while (ppos) {
    if (value < ppos->value) {
      pos = ppos;
      ppos = ppos->left;
    } else if (value > ppos->value) {
      pos = ppos;
      ppos = ppos->right;
    } else {
      // value == ppos->value
      return ppos;
    }
  }
  return pos;
}

bool btree_search(btree_t tree, uint64_t target) {
  if (!tree->size) return false;
  btree_node_p node = search_node(tree->root, target);
  return node ? (node->value == target) : false;
}

bool btree_insert(btree_t tree, uint64_t value) {
  if (!tree->size) {
    tree->root = btree_node_alloc(tree, value);
    return true;
  }
  btree_node_p node = search_node(tree->root, value);
  if (value < node->value) {
    node->left = btree_node_alloc(tree, value);
    return true;
  } else if (value > node->value) {
    node->right = btree_node_alloc(tree, value);
    return true;
  } else {
    return false;
  }
}