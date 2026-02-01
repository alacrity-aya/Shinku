#include "cache.skel.h"
#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>

int main() {
  struct cache_bpf *skel = cache_bpf__open_and_load();
  if (!skel)
    return 1;

  cache_bpf__attach(skel);
  printf("Cache monitor loaded. Press Ctrl+C to exit.\n");

  while (1) {
    sleep(1);
  }

  cache_bpf__destroy(skel);
  return 0;
}
