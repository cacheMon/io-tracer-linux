# Page Cache Events

**Description:** Captures page cache operations including hits, misses, dirty pages, writebacks, evictions, invalidations, readahead, and memory reclaim. Enhanced with file context and size information for better analysis.

**Kernel Probes Attached (kernel version dependent):**
- **Cache Miss:** `filemap_add_folio` (5.14+) / `add_to_page_cache_lru` (older)
- **Cache Hit:** `folio_mark_accessed` (5.14+) / `mark_page_accessed` (older)
- **Dirty Page:** `__folio_mark_dirty` (5.14+) / `account_page_dirtied` (older)
- **Writeback Start:** `folio_clear_dirty_for_io` (5.14+) / `clear_page_dirty_for_io` (older)
- **Writeback End:** `folio_end_writeback` / `__folio_end_writeback` / `test_clear_page_writeback`
- **Eviction:** `filemap_remove_folio` / `__delete_from_page_cache`
- **Invalidation:** `invalidate_mapping_pages` / `truncate_inode_pages_range`
- **Readahead:** `__do_page_cache_readahead` / `page_cache_ra_order` (5.16+)
- **Reclaim:** `shrink_folio_list` (5.16+) / `shrink_page_list` (older)

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | PID | `u32` | Process ID that triggered the event |
| 3 | Command | `string` | Process name (max 16 characters) |
| 4 | Event Type | `string` | Cache event type (see table below) |
| 5 | Inode | `u64` | File inode number; empty if `0` |
| 6 | Page Index | `u64` | Page offset within file (file offset / PAGE_SIZE); empty if `0` |
| 7 | Size | `u32` | File size in pages (from `inode->i_size >> 12`) |
| 8 | CPU ID | `u32` | CPU where event occurred |
| 9 | Device ID | `u32` | Device ID from the file's superblock |
| 10 | Count | `u32` | Number of pages affected by the operation (1 for single-page, N for bulk) |
| 11 | mono_ns | `u64` | Record time in `CLOCK_MONOTONIC` nanoseconds (kernel `bpf_ktime_get_ns()`) — the common cross-stream correlation clock; add the manifest's `clock.mono_to_real_offset_ns` to recover wall-clock ns. |

## Event Types

| ID | Value | Description |
|----|-------|-------------|
| 0 | `HIT` | Page was found in cache (no disk I/O needed) |
| 1 | `MISS` | Page was not in cache (disk read required) |
| 2 | `DIRTY` | Page marked as dirty (modified in memory, needs writeback) |
| 3 | `WRITEBACK_START` | Dirty page writeback to disk initiated |
| 4 | `WRITEBACK_END` | Dirty page writeback to disk completed |
| 5 | `EVICT` | Page evicted from cache (LRU pressure) |
| 6 | `INVALIDATE` | Pages explicitly invalidated (truncate/sync) |
| 7 | `DROP` | Page dropped from cache explicitly |
| 8 | `READAHEAD` | Pages prefetched into cache by readahead |
| 9 | `RECLAIM` | Pages reclaimed under memory pressure (kswapd/direct reclaim) |

**Output File:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/cache/cache_*.csv`

**Important Limitation — Filename Resolution:**
The filename is **not captured** for cache events due to eBPF constraints. Cache events provide only: folio/page → address_space → inode. Resolving inode → filename requires traversing `inode->i_dentry` (a linked list of hard links), which is impractical in eBPF. Use inode numbers to correlate with VFS events or filesystem snapshots.

**Note:** Cache events can be sampled using `--cache-sample-rate N` to reduce overhead (captures 1 in N events).
