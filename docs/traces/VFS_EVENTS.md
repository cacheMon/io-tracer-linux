# VFS (Virtual File System) Events

**Description:** Captures file system operations at the VFS layer, intercepting all file access operations regardless of the underlying filesystem.

**Kernel Probes Attached:**
- `do_sys_openat2` (entry) — Captures the user-provided filename string before kernel resolution
- `do_sys_openat2` (return) — Captures the allocated file descriptor after a successful open
- `vfs_open` — File open operations (inode and flags)
- `vfs_read` (entry + return) — File read operations; the return probe records bytes read / errno and latency
- `vfs_write` (entry + return) — File write operations; the return probe records bytes written / errno and latency
- `vfs_fsync` / `vfs_fsync_range` — File sync operations
- `vfs_unlink` — File deletion operations
- `vfs_getattr` — File attribute queries
- `do_mmap` / `__vm_munmap` — Memory-mapped file operations
- `iterate_dir` — Directory listing operations
- `do_truncate` — File truncation operations
- `vfs_rename` — File/directory rename operations
- `vfs_mkdir` — Directory creation operations
- `vfs_rmdir` — Directory removal operations
- `vfs_link` — Hard link creation operations
- `vfs_symlink` — Symbolic link creation operations
- `vfs_fallocate` — File space pre-allocation operations
- `do_sendfile` / `__do_sendfile` — Efficient file-to-file transfer operations

> **io_uring-origin rows:** `READ`/`WRITE` operations issued via io_uring bypass `vfs_read`/`vfs_write` (they call `->read_iter`/`->write_iter` directly), so they are mirrored into this trace from the io_uring instrumentation rather than captured by a VFS probe. They use the same schema; their `flags` column carries io_uring SQE flags (`FIXED_FILE|ASYNC|…`) instead of `O_*` flags, and `ppid`/`container_id` are empty. See [IO_URING_EVENTS.md](IO_URING_EVENTS.md#mirroring-into-the-fsvfs-trace). There is no separate io_uring output stream; the fs mirror is the only place these rows appear.

## Filename Resolution

The `filename` field contains the best available path for the file at event time. Full absolute paths are resolved entirely inside the kernel at probe time before the process can exit, so even output from short-lived processes (e.g. `cat`, `ls`) contains correct paths.

### Resolution Pipeline

Resolution is attempted in priority order for each event type:

```
OPEN events
───────────
①  do_sys_openat2 kprobe (entry)
   └─ bpf_probe_read_user_str(filename_arg)
      → full path if the caller passed an absolute path  (e.g. /etc/ld.so.cache)
      → relative path or basename if caller used a relative path

②  vfs_open kprobe (using result from ①)
   ├─ if staged path starts with '/'  →  use it as filename, cache inode→path
   └─ else  →  fall back to d_name (basename from dentry)

③  do_sys_openat2 kretprobe (return)
   └─ inserts real fd into the event, cleans up staging maps; emits to perf

Non-OPEN events  (READ, WRITE, CLOSE, MMAP, etc.)
──────────────────────────────────────────────────
④  inode_to_path cache  (populated by ① during OPEN events)
   ├─ cache hit  →  full absolute path
   └─ cache miss →  basename from d_name (the dentry short name)

MMAP/MUNMAP post-processing
───────────────────────────
⑤  userspace mmap region cache  (populated by MMAP events)
   ├─ key: PID + mapping start address
   ├─ value: mapping end address + filename
   └─ used by MUNMAP to recover the filename for the unmapped region

`MMAP` stores the actual mapping start returned by `do_mmap` (via kretprobe), not
the caller's requested hint address. This is required for joining later
`MUNMAP` events for non-`MAP_FIXED` mappings.
```

### File Descriptor Field

For `OPEN` events the `fd` column (last column) contains the allocated file descriptor number returned by the `openat` syscall. This is guaranteed to match the fd seen by userspace. For all other event types this field is `0`.

### MUNMAP Filename Resolution Implementation

`MUNMAP` does not expose a `struct file *` or inode in the probed kernel path, so the tracer cannot resolve its filename directly in eBPF. The implementation therefore uses a two-stage join across `MMAP` and `MUNMAP` events:

1. `do_mmap` kprobe (`trace_mmap_entry`) captures file-backed mapping metadata:
   - `PID`
   - `filename`
   - `inode`
   - `length`
   - `mmap_prot`
   - `mmap_flags`
2. That partial event is stored in the BPF `mmap_staging` map, keyed by `pid_tgid`.
3. `do_mmap` kretprobe (`trace_mmap_ret`) reads the actual return value from `do_mmap`.
   - On success, the return value is the real mapping start address.
   - On failure, the staged entry is discarded.
4. Userspace receives the completed `MMAP` event and stores it in `IOTracer.mmap_regions`, keyed by:
   - `PID`
   - mapping start address
5. The cached value stores:
   - mapping end address
   - resolved filename
6. When `__vm_munmap` fires, the kernel event only carries:
   - `PID`
   - unmapped start address
   - unmapped length
7. Userspace looks up the tracked region whose address range contains the unmapped start address and copies that region's filename into the `MUNMAP` CSV row.
8. After a match, the cached region is updated:
   - full unmap: remove the region
   - prefix/suffix unmap: shrink the region
   - middle unmap: split the region into two tracked regions

This is why the `address` column matters for both `MMAP` and `MUNMAP`: it is the join key that lets userspace recover filenames for unmap events.

### Caveats

#### Relative paths remain relative
If a process opens a file with a relative path (e.g. `openat(AT_FDCWD, "data/output.txt", ...)`) the captured string is `data/output.txt`, not the absolute path. This is common for application-level file opens. Library and system file opens (by the dynamic linker etc.) always use absolute paths and are always fully resolved.

#### Empty `flags` is normal for some non-`MMAP` events
The `flags` column may be empty even for non-`MMAP` operations. This is expected for several reasons:

- Some probes intentionally emit `flags = 0`, so the CSV `flags` field is blank.
- Some probes do not assign `flags`, so the zero-initialized default is emitted as blank.
- Dual-path operations (`RENAME`, `LINK`, `SYMLINK`) are emitted via the dual-event path and currently emit `flags = 0`.

Operations that currently have no rendered `flags` value:

- `MUNMAP`
- `GETATTR`
- `SETATTR`
- `CHDIR`
- `UNLINK`
- `TRUNCATE`
- `SYNC`
- `RENAME`
- `RMDIR`
- `LINK`
- `SYMLINK`
- `SENDFILE`
- `DIO_READ`
- `DIO_WRITE`
- `PROCESS_EXEC`
- `PROCESS_EXIT`

So an empty `flags` field does not necessarily mean missing instrumentation; it can also mean the operation does not define a printable flag value for that event.

#### Kernel-internal and exec-path opens bypass the syscall entry probe
Opens triggered by the kernel itself (e.g. during `execve` loading the ELF interpreter, or kernel module loading) do not go through `do_sys_openat2`. For these, only the `d_name` basename is available in the filename field.

#### Inode cache is process-lifetime scoped
The `inode → path` cache populated by OPEN events is held in memory for the tracer session. It covers any file that was opened while the tracer was running. Files opened before the tracer started will only have basenames for non-OPEN events unless an OPEN event for that inode is also captured.

#### MUNMAP filename recovery is best-effort
`MUNMAP` does not provide file context in the kernel probe. The tracer recovers the filename in userspace by matching the `PID` and unmapped address against previously seen `MMAP` regions. This works for exact unmaps and partial unmaps of tracked regions, but it cannot recover filenames for mappings that existed before tracing started or for missed `MMAP` events.

#### Hard links
A single inode can have multiple paths. The cache stores whichever absolute path was seen first. For files with multiple hard links, the filename may not match the specific link name used by the accessing process.

#### Inode reuse after deletion
If a file is deleted and a new file is created with the same inode number, the cache may return the old path for new events. This is uncommon during a single trace session but can occur in high-churn workloads. The `inode` field can be used to detect this.

#### Path length truncation
Filenames are capped at **256 bytes** (`FILENAME_MAX_LEN` in `prober.c`). Paths longer than 255 characters are silently truncated at the buffer boundary. Deeply nested paths (e.g. inside Docker layer directories) may be affected.

#### On-disk path vs. mount namespace path
The path captured is relative to the mount namespace of the probed process. In container environments this may differ from the host path for the same file.



| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`), derived from the kernel's per-event `bpf_ktime_get_ns()` (CLOCK_MONOTONIC) converted to wall-clock. This is the time the event actually occurred, so rows are correctly ordered when sorted by this column even though the per-CPU perf buffers deliver them in batches. |
| 2 | Operation | `string` | VFS operation type (see table below) |
| 3 | PID | `u32` | Process ID |
| 4 | Command | `string` | Process name (max 16 characters) |
| 5 | Filename | `string` | File path; for dual-path operations (`RENAME`, `LINK`, `SYMLINK`) formatted as `old_path -> new_path`. For `OPEN`, the path is resolved to absolute via `/proc/<pid>/fd`; if that races (fd already closed) and the captured path was relative, it is resolved against the openat `dirfd` / process cwd as a fallback |
| 6 | Size (requested) | `u64` | **Requested** I/O size in bytes — the `count` argument to `read`/`write` (or operation size for others); `0` for non-I/O operations. The **actual** bytes transferred are in column 17 (`bytes_completed`), which can be smaller (short read/write). |
| 7 | Inode | `u64` | File inode number; empty if `0` |
| 8 | Flags | `string` | Operation-specific flags for non-MMAP operations (see tables below); empty when the operation has no defined flag value to render |
| 9 | Offset | `u64` | File offset for positioned I/O; empty if `0` |
| 10 | TID | `u32` | Thread ID for multi-threaded correlation; empty if `0` |
| 11 | mmap_prot | `string` | MMAP protection flags (`PROT_*`, pipe-separated); empty for non-MMAP operations |
| 12 | mmap_flags | `string` | MMAP mapping flags (`MAP_*`, pipe-separated); empty for non-MMAP operations |
| 13 | address | `string` | Mapping start address as hex (`0x...`) for `MMAP` and `MUNMAP`; for `MREMAP` formatted as `old_address -> new_address`; empty for other operations |
| 14 | cmdline | `string` | Full command line (`argv` joined by spaces) of the process that triggered the event; empty if unresolvable (see below) |
| 15 | return_value | `s64` | Raw syscall return value for `READ`/`WRITE` (bytes moved if `>= 0`, negative `errno` on failure); empty for other operations |
| 16 | errno | `string` | Error name (e.g. `EAGAIN`) when a `READ`/`WRITE` failed (`return_value < 0`); empty on success or for other operations |
| 17 | bytes_completed (actual) | `u64` | **Actual** bytes read/written for `READ`/`WRITE` (`return_value` when `>= 0`); compare against column 6 (`Size (requested)`) to detect short I/O. Empty on failure or for other operations |
| 18 | duration_ns | `u64` | Operation duration in nanoseconds (entry → return) for `READ`/`WRITE`; empty for other operations |
| 19 | device | `string` | Backing device of the file as `major:minor` (from `super_block->s_dev`); populated for `READ`/`WRITE`/`OPEN`; empty otherwise |
| 20 | ppid | `u32` | Parent process ID (`real_parent->tgid`); populated for `READ`/`WRITE`/`OPEN`; empty otherwise |
| 21 | container_id | `u64` | cgroup v2 id of the process (container identifier); populated for `READ`/`WRITE`/`OPEN`; empty otherwise |
| 22 | fs_type | `string` | Source filesystem name derived from the superblock magic (e.g. `EXT2/3/4`, `XFS`, `BTRFS`, `OVERLAYFS`, `NFS`), letting physical-disk I/O be distinguished from network/overlay sources; populated for `READ`/`WRITE`/`OPEN`; empty otherwise |
| 23 | mono_ns | `u64` | Record time in `CLOCK_MONOTONIC` nanoseconds (kernel `bpf_ktime_get_ns()`) — the common clock for correlating across streams. Add the manifest's `clock.mono_to_real_offset_ns` to recover wall-clock ns. |

> **Note on filesystem classification (`fs_type`) and sockets:** virtual/pseudo filesystems (procfs, sysfs, tmpfs, cgroupfs, debugfs, …) and sockets/pipes are filtered out at the eBPF layer by `is_regular_file()`, so they never appear as fs-trace rows. Their *absence* is the signal that an access was virtual/socket I/O rather than physical filesystem I/O. The `fs_type` column then names the concrete backing filesystem of the events that do appear, so physical-disk filesystems (`EXT2/3/4`, `XFS`, `BTRFS`, …) can be told apart from network (`NFS`, `CIFS`) and container-overlay (`OVERLAYFS`) sources.

## `cmdline` Field

The `cmdline` field is populated for **all** VFS operation types, not just process lifecycle events. It is read from `/proc/<pid>/cmdline` in userspace and provides the full argument vector (`argv[0] argv[1] …`) of the process that triggered the event.

### Resolution Pipeline

```
For every VFS event:
  ① Check per-PID cmdline cache (self.cmdline_cache)
     └─ cache hit  →  return cached value immediately
     └─ cache miss →  read /proc/<pid>/cmdline

  ② /proc/<pid>/cmdline read
     ├─ success  →  store in cache, return value
     └─ failure  →  return "" (process already dead, cache never populated)
```

Cmdline is read **before** any process lifecycle handling (including `PROCESS_EXIT` cache eviction), so the `PROCESS_EXIT` row itself always carries the correct value when the cache was populated.

### Cache Eviction Policy

| Trigger | Eviction |
|---------|----------|
| `PROCESS_EXEC` | Evict — `execve()` replaces `argv`; next read picks up the new cmdline |
| `PROCESS_EXIT` | **No eviction** — `CLOSE` events buffered after `PROCESS_EXIT` still resolve from cache |
| PID reuse | Handled implicitly by the `PROCESS_EXEC` eviction on the new process |

### Caveats

#### Extremely short-lived processes
If a process completes entirely within a single perf-buffer batch (spawned and exited before userspace drains the ring buffer), all its events may arrive after `/proc/<pid>/cmdline` is already gone and before any earlier event had a chance to populate the cache. The `cmdline` field will be empty for every event from that process.

#### Long command lines are truncated
`cmdline` is capped at **512 characters**. Command lines longer than this are truncated with a trailing `...`. This can affect processes launched with many arguments (e.g. shell glob expansions, `find` with long predicate chains).

#### `argv[0]` as filename fallback for `PROCESS_EXEC`
For `PROCESS_EXEC` events, if the `filename` field is empty (the eBPF probe did not capture a path), `argv[0]` from `cmdline` is used as the filename. This provides best-effort attribution of the executed binary when kernel-side resolution fails (e.g. kernel-internal `execve` calls that bypass `do_sys_openat2`).

#### `comm` vs `cmdline`
The `command` field (column 4) is the short process name captured in-kernel by eBPF (`task->comm`, max 16 chars). The `cmdline` field is the full argument vector read from `/proc` in userspace. For processes that use `prctl(PR_SET_NAME, ...)` to rename themselves, `comm` may differ from `argv[0]`.



## Operation Types

| Code | Operation | Kernel Function | Description |
|------|-----------|-----------------|-------------|
| 1 | `READ` | `vfs_read()` | Read data from a file |
| 2 | `WRITE` | `vfs_write()` | Write data to a file |
| 3 | `OPEN` | `vfs_open()` | Open a file descriptor |
| 4 | `CLOSE` | `fput()` | Close/release a file descriptor |
| 5 | `FSYNC` | `vfs_fsync()` | Flush file data to storage |
| 6 | `MMAP` | `mmap_region()` | Memory-map a file |
| 7 | `MUNMAP` | `vm_munmap()` | Unmap a memory-mapped region |
| 8 | `GETATTR` | `vfs_getattr()` | Query file attributes (stat) |
| 9 | `SETATTR` | `vfs_setattr()` | Set file attributes (chmod, chown) |
| 10 | `CHDIR` | `sys_chdir()` | Change working directory |
| 11 | `READDIR` | `iterate_dir()` | Read directory entries |
| 12 | `UNLINK` | `vfs_unlink()` | Delete a file |
| 13 | `TRUNCATE` | `vfs_truncate()` | Truncate file to a given size |
| 14 | `SYNC` | `ksys_sync()` | System-wide filesystem sync |
| 15 | `RENAME` | `vfs_rename()` | Rename or move a file/directory (dual-path: `old -> new`) |
| 16 | `MKDIR` | `vfs_mkdir()` | Create a directory |
| 17 | `RMDIR` | `vfs_rmdir()` | Remove an empty directory |
| 18 | `LINK` | `vfs_link()` | Create a hard link (dual-path: `existing -> link`) |
| 19 | `SYMLINK` | `vfs_symlink()` | Create a symbolic link (dual-path: `target -> link`) |
| 20 | `FALLOCATE` | `vfs_fallocate()` | Pre-allocate file space |
| 21 | `SENDFILE` | `do_sendfile()` | Zero-copy file-to-socket transfer |
| 22 | `SPLICE` | `splice()` | Zero-copy pipe transfer |
| 23 | `VMSPLICE` | `vmsplice()` | Splice user pages to pipe |
| 24 | `MSYNC` | `msync()` | Sync memory-mapped region to disk |
| 25 | `MADVISE` | `madvise()` | Provide memory usage advice to kernel |
| 26 | `DIO_READ` | Direct I/O path | Direct I/O read (bypasses page cache) |
| 27 | `DIO_WRITE` | Direct I/O path | Direct I/O write (bypasses page cache) |
| 28 | `MREMAP` | `sys_mremap()` | Remap/move/resize a memory region |
| 29 | `PROCESS_EXEC` | `sched_process_exec` | Process executed new image (address space wiped) |
| 30 | `PROCESS_EXIT` | `sched_process_exit` | Process terminated |

**Dual-Path Operations:** `RENAME`, `LINK`, and `SYMLINK` include both source and destination values in the filename field, formatted as `old_path -> new_path`. For `SYMLINK`, this is `target -> link`.

## Flags Coverage

The tracer currently uses the `flags`-related columns as follows:

- `OPEN`: file open flags are rendered in the generic `flags` column.
- `READ`: file handle flags are rendered in the generic `flags` column using the same `O_*` decoding as `OPEN`.
- `WRITE`: file handle flags are rendered in the generic `flags` column using the same `O_*` decoding as `OPEN`.
- `CLOSE`: file handle flags are rendered in the generic `flags` column using the same `O_*` decoding as `OPEN`.
- `FSYNC`: file handle flags are rendered in the generic `flags` column using the same `O_*` decoding as `OPEN`.
- `READDIR`: directory file handle flags are rendered in the generic `flags` column using the same `O_*` decoding as `OPEN`.
- `MMAP`: protection and mapping flags are rendered in `mmap_prot` and `mmap_flags`; the generic `flags` column is unused.
- `MKDIR`: mode bits are rendered in the generic `flags` column as `S_*` names.
- `FALLOCATE`: `FALLOC_FL_*` mode bits are rendered in the generic `flags` column.
- `SPLICE`: `SPLICE_F_*` bits are rendered in the generic `flags` column.
- `VMSPLICE`: `SPLICE_F_*` bits are rendered in the generic `flags` column when emitted.
- `MSYNC`: `MS_*` bits are rendered in the generic `flags` column.
- `MADVISE`: `MADV_*` behavior values are rendered in the generic `flags` column.
- `MREMAP`: `MREMAP_*` bits are rendered in the generic `flags` column.


For `READ`, `WRITE`, `CLOSE`, `FSYNC`, and `READDIR`, the decoded flag set is derived from the open file description's `file->f_flags` field in the kernel. These are the flags originally supplied to `open()` and therefore use the same `O_*` names as OPEN events.

For `MKDIR`, the decoded value comes from the `mode` argument and may include:

- File type bits such as `S_IFDIR`
- Permission bits such as `S_IRUSR`, `S_IWUSR`, `S_IXUSR`, `S_IRGRP`, `S_IXGRP`, `S_IROTH`, `S_IXOTH`
- Special mode bits such as `S_ISUID`, `S_ISGID`, `S_ISVTX`

## File Open Flags

Displayed for `OPEN` operations. Multiple flags are combined with `|` (pipe):

| Flag | Octal | Description |
|------|-------|-------------|
| `O_RDONLY` | `0o000` | Open for reading only |
| `O_WRONLY` | `0o001` | Open for writing only |
| `O_RDWR` | `0o002` | Open for reading and writing |
| `O_CREAT` | `0o100` | Create file if it does not exist |
| `O_EXCL` | `0o200` | Fail if file already exists (with O_CREAT) |
| `O_NOCTTY` | `0o400` | Do not assign controlling terminal |
| `O_TRUNC` | `0o1000` | Truncate file to zero length |
| `O_APPEND` | `0o2000` | Append writes to end of file |
| `O_NONBLOCK` | `0o4000` | Non-blocking I/O mode |
| `O_DSYNC` | `0o10000` | Synchronized data writes |
| `O_DIRECT` | `0o40000` | Direct I/O (bypass page cache) |
| `O_LARGEFILE` | `0o100000` | Allow large files (>2 GB on 32-bit) |
| `O_DIRECTORY` | `0o200000` | Fail if not a directory |
| `O_NOFOLLOW` | `0o400000` | Do not follow symbolic links |
| `O_NOATIME` | `0o1000000` | Do not update access time |
| `O_CLOEXEC` | `0o2000000` | Close file descriptor on exec |
| `O_SYNC` | `0o4010000` | Synchronized I/O (data + metadata) |
| `O_PATH` | `0o10000000` | Open for path operations only (no I/O) |
| `O_TMPFILE` | `0o20200000` | Create unnamed temporary file |

## Mmap Flags

Displayed for `MMAP` operations using dedicated columns:
- `mmap_prot`: protection flags (`PROT_*`)
- `mmap_flags`: mapping flags (`MAP_*`)

The generic `flags` column is not used for `MMAP` events.

### Protection Flags

| Flag | Hex | Description |
|------|-----|-------------|
| `PROT_NONE` | `0x0` | No access allowed |
| `PROT_READ` | `0x1` | Pages can be read |
| `PROT_WRITE` | `0x2` | Pages can be written |
| `PROT_EXEC` | `0x4` | Pages can be executed |

### Mapping Flags

| Flag | Hex | Description |
|------|-----|-------------|
| `MAP_SHARED` | `0x01` | Share mapping with other processes |
| `MAP_PRIVATE` | `0x02` | Create private copy-on-write mapping |
| `MAP_FIXED` | `0x10` | Place mapping at exact address |
| `MAP_ANONYMOUS` | `0x20` | Not backed by a file |
| `MAP_GROWSDOWN` | `0x0100` | Stack-like mapping that grows downward |
| `MAP_DENYWRITE` | `0x0800` | Deny write access to the file (ignored) |
| `MAP_EXECUTABLE` | `0x1000` | Mark mapping as executable (ignored) |
| `MAP_LOCKED` | `0x2000` | Lock pages in memory (no swap) |
| `MAP_NORESERVE` | `0x4000` | Do not reserve swap space |
| `MAP_POPULATE` | `0x8000` | Pre-fault pages into memory |
| `MAP_NONBLOCK` | `0x10000` | Do not block on I/O during populate |
| `MAP_STACK` | `0x20000` | Allocate at address suitable for stack |
| `MAP_HUGETLB` | `0x40000` | Use huge pages |

## Fallocate Flags

Displayed for `FALLOCATE` operations:

| Flag | Hex | Description |
|------|-----|-------------|
| `FALLOC_FL_KEEP_SIZE` | `0x01` | Allocate space without changing file size |
| `FALLOC_FL_PUNCH_HOLE` | `0x02` | Punch a hole (deallocate space) |
| `FALLOC_FL_COLLAPSE_RANGE` | `0x08` | Collapse a range (remove without leaving hole) |
| `FALLOC_FL_ZERO_RANGE` | `0x10` | Zero-fill a range |
| `FALLOC_FL_INSERT_RANGE` | `0x20` | Insert a range (shift data) |
| `FALLOC_FL_UNSHARE_RANGE` | `0x40` | Unshare shared extents (CoW) |

## Msync Flags

Displayed for `MSYNC` operations:

| Flag | Value | Description |
|------|-------|-------------|
| `MS_ASYNC` | 1 | Schedule writeback asynchronously |
| `MS_INVALIDATE` | 2 | Invalidate cached copies |
| `MS_SYNC` | 4 | Synchronous writeback (block until complete) |

## Madvise Behaviors

Displayed for `MADVISE` operations:

| Flag | Value | Description |
|------|-------|-------------|
| `MADV_NORMAL` | 0 | No special treatment (default) |
| `MADV_RANDOM` | 1 | Expect random access pattern |
| `MADV_SEQUENTIAL` | 2 | Expect sequential access pattern |
| `MADV_WILLNEED` | 3 | Will need these pages soon (trigger readahead) |
| `MADV_DONTNEED` | 4 | Do not need these pages (may be freed) |
| `MADV_FREE` | 8 | Pages can be freed when memory is needed |
| `MADV_REMOVE` | 9 | Remove pages and backing storage |
| `MADV_DONTFORK` | 10 | Do not inherit across fork |
| `MADV_DOFORK` | 11 | Inherit across fork (undo DONTFORK) |
| `MADV_MERGEABLE` | 12 | Enable KSM (Kernel Same-page Merging) |
| `MADV_UNMERGEABLE` | 13 | Disable KSM |
| `MADV_HUGEPAGE` | 14 | Enable Transparent Huge Pages |
| `MADV_NOHUGEPAGE` | 15 | Disable Transparent Huge Pages |
| `MADV_DONTDUMP` | 16 | Exclude from core dump |
| `MADV_DODUMP` | 17 | Include in core dump (undo DONTDUMP) |
| `MADV_WIPEONFORK` | 18 | Wipe pages on fork (security) |
| `MADV_KEEPONFORK` | 19 | Keep pages on fork (undo WIPEONFORK) |
| `MADV_COLD` | 20 | Hint that pages are cold (deactivate) |
| `MADV_PAGEOUT` | 21 | Hint to page out to swap |
| `MADV_POPULATE_READ` | 22 | Populate (fault in) pages for reading |
| `MADV_POPULATE_WRITE` | 23 | Populate (fault in) pages for writing |

## Mremap Flags

Displayed for `MREMAP` operations:

| Flag | Hex | Description |
|------|-----|-------------|
| `MREMAP_MAYMOVE` | `0x1` | Allow mapping to be moved to a new address |
| `MREMAP_FIXED` | `0x2` | Place mapping at exact address |
| `MREMAP_DONTUNMAP` | `0x4` | Do not unmap the old mapping |

## Empty Filenames

In some cases, the filename field may be empty. This occurs when the kernel data structures required for path resolution are unavailable or inaccessible. Common reasons include:

**1. Null or Invalid Dentry**
- The file's dentry (directory entry) structure is NULL or invalid
- Occurs during race conditions when files are being deleted or during unusual kernel states
- More common with short-lived temporary files or anonymous file descriptors

**2. Anonymous File Descriptors**
- Pipes and sockets (not backed by regular files)
- Anonymous memory mappings (`MAP_ANONYMOUS` without a backing file)
- memfd and other in-memory file descriptors
- File descriptors created via `O_TMPFILE` before being linked to the filesystem

**3. Early/Late Lifecycle Events**
- File descriptor operations during process creation or teardown
- Operations on file descriptors that are in the process of being closed
- Race conditions between file deletion and ongoing operations

**4. Virtual/Pseudo Filesystems**
- Some operations on procfs (`/proc`), sysfs (`/sys`), or other virtual filesystems
- These are filtered out by default, but edge cases may occur during the filtering check

**5. eBPF Probe Read Failures**
- Kernel memory read restrictions in hardened kernels
- Memory paging issues where the dentry name is swapped out
- Corruption or transient kernel data structure states

**6. Userspace Decode Failures**
- Unicode decode errors when the filename contains invalid UTF-8 sequences
- Non-standard character encodings in filenames
- Binary or corrupted data in the filename buffer

**Analysis Recommendations:**
- Empty filenames are typically safe to filter out for filesystem I/O analysis
- For network and IPC analysis, empty filenames are expected for sockets and pipes
- Check the inode field — if it's non-zero, the file exists but the path couldn't be resolved
- Correlate with the operation type and process command to determine if the empty filename is expected

**Output File:** `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/fs/fs_*.csv.zst`
