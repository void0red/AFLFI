//
// Created by void0red on 23-3-1.
//
#include "btree.h"

static inline size_t capacity_grow(size_t old) {
  return 2 * old;
}

static inline btree_node_p btree_node_alloc(btree_t tree, uint32_t val) {
  btree_node_p node = calloc(1, sizeof(*node));
  if (unlikely(!node)) FATAL("calloc failed");
  node->value = val;
  if (tree->size >= tree->capacity) {
    tree->capacity = capacity_grow(tree->capacity);
    tree->values = realloc(tree->values, sizeof(uint32_t) * tree->capacity);
  }
  tree->values[tree->size++] = val;
  return node;
}

btree_t btree_create() {
  btree_t ret = calloc(1, sizeof(*ret));
  if (unlikely(!ret)) FATAL("calloc failed");
  ret->capacity = 1;
  ret->values = malloc(sizeof(uint32_t));
  return ret;
}

static inline void btree_node_free(btree_node_p node) {
  if (!node) return;

  struct rb_node *left = node->node.rb_left;
  if (left) {
    btree_node_free(rb_entry(left, btree_node_t, node));
    node->node.rb_left = NULL;
  }
  struct rb_node *right = node->node.rb_right;
  if (right) {
    btree_node_free(rb_entry(right, btree_node_t, node));
    node->node.rb_right = NULL;
  }
  free(node);
}

void btree_destroy(btree_t tree) {
  if (tree->root.rb_node)
    btree_node_free(rb_entry(tree->root.rb_node, btree_node_t, node));
  free(tree->values);
  free(tree);
}

bool btree_insert(btree_t tree, uint32_t value) {
  struct rb_node **new = &(tree->root.rb_node), *parent = NULL;
  while (*new) {
    btree_node_p this = rb_entry(*new, btree_node_t, node);
    parent = *new;
    if (value < this->value) {
      new = &((*new)->rb_left);
    } else if (value > this->value) {
      new = &((*new)->rb_right);
    } else {
      return false;
    }
  }
  btree_node_p data = btree_node_alloc(tree, value);
  rb_link_node(&data->node, parent, new);
  rb_insert_color(&data->node, &tree->root);
  return true;
}