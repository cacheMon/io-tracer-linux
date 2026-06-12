/**
 * @file prober.c
 * @brief eBPF-based I/O Tracer for comprehensive system I/O monitoring
 *
 * This BPF program implements a multi-layer I/O tracing system that monitors:
 * - VFS (Virtual File System) operations: read, write, open, close, fsync, etc.
 * - Block layer events: request queuing, issue, and completion with latency
 * - Page cache operations: hits, misses, dirty pages, writeback, eviction
 * - Memory-mapped I/O: page faults, msync, madvise
 * - Async I/O: direct I/O, splice
 *
 * The tracer uses BCC (BPF Compiler Collection) and attaches to kernel
 * functions via kprobes, kretprobes, and tracepoints.
 *
 * @note Requires CAP_SYS_ADMIN or CAP_BPF capability to load
 * @note Kernel version compatibility macros handle API differences
 */

#define BPF_NO_KFUNC_PROTO
#include <linux/ptrace.h>

/* ============================================================================
 * KERNEL VERSION COMPATIBILITY
 * ============================================================================
 * These macros and struct placeholders ensure compatibility across different
 * kernel versions by providing missing definitions.
 */

/* ----------------------------------------------------------------------------
 * BPF "special field" type compatibility
 * ----------------------------------------------------------------------------
 * <linux/bpf.h> defines btf_field_type_size() / btf_field_type_align() as
 * static inline functions that apply sizeof()/__alignof__() to a family of
 * special-field structs: bpf_timer, bpf_wq, bpf_task_work, bpf_list_head,
 * bpf_list_node, bpf_rb_root, bpf_rb_node, bpf_refcount.
 *
 * That header is pulled into this BPF program transitively
 * (net/sock.h -> linux/security.h -> linux/bpf.h). Depending on the kernel,
 * some of these structs are only *forward-declared* in the headers BCC sees,
 * so sizeof()/__alignof__() fail with "invalid application ... to an
 * incomplete type". The program never instantiates these structs, so an empty
 * placeholder is enough to complete the type for the compiler.
 *
 * We can only declare the ones the headers leave incomplete: defining a
 * placeholder for a struct the headers already define fully is a redefinition
 * error, and there is no preprocessor test for "is this type complete?".
 * Hence the per-version guards below.
 *
 * MAINTENANCE: if a future kernel fails to compile with
 *   "invalid application of 'sizeof' to an incomplete type 'struct bpf_<X>'"
 * add `struct bpf_<X> {};` here under the matching version guard. The
 * authoritative list lives in btf_field_type_size() in <linux/bpf.h>.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
struct bpf_timer {};       /* bpf_timer field, forward-declared from 5.17 on */
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
struct bpf_wq {};          /* workqueue field, added in 6.14 */
struct bpf_task_work {};   /* task_work field, added in 6.14 */
#endif

/* BPF atomic load/store instructions - fallback definitions */
#ifndef BPF_LOAD_ACQ
#define BPF_LOAD_ACQ 0xe1  /**< Atomic load with acquire semantics */
#endif

#ifndef BPF_STORE_REL
#define BPF_STORE_REL 0xe2  /**< Atomic store with release semantics */
#endif

#ifndef BPF_PSEUDO_FUNC
#define BPF_PSEUDO_FUNC 4  /**< Pseudo function for BPF-to-BPF calls */
#endif

#ifndef BPF_F_BROADCAST
#define BPF_F_BROADCAST (1ULL << 3)  /**< Broadcast flag for BPF maps */
#endif

/* ============================================================================
 * KERNEL HEADERS
 * ============================================================================
 * Required kernel headers for accessing kernel data structures and functions.
 */

#include <linux/blk_types.h>  /* Block layer types (bio, request) */
#include <linux/blkdev.h>     /* Block device structures */
#include <linux/dcache.h>     /* Dentry cache structures for path resolution */
#include <linux/fdtable.h>    /* files_struct, fdtable — full definitions for fd-to-file lookup */
#include <linux/fs.h>         /* VFS structures (file, inode, super_block) */
#include <linux/fs_struct.h>  /* Process filesystem context (pwd, root) */
#include <linux/in.h>         /* IPv4 socket address structures */
#include <linux/in6.h>        /* IPv6 socket address structures */
#include <linux/mm.h>         /* Memory management (page, vm_area_struct) */
#include <linux/sched.h>      /* Process/task structures */
#include <linux/stat.h>       /* File mode/permission macros (S_ISREG, etc.) */
#include <linux/tcp.h>        /* TCP protocol structures */
#include <linux/udp.h>        /* UDP protocol structures */
#include <linux/uio.h>        /* iov_iter — direct I/O direction detection */
#include <net/inet_sock.h>    /* Internet socket structures */
#include <net/sock.h>         /* Generic socket structures */

/* Block multi-queue header - only available in kernel 5.16+ */
#ifdef __has_include
#if __has_include(<linux/blk-mq.h>)
#include <linux/blk-mq.h>  /* Block layer multi-queue structures */
#endif
#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
#include <linux/blk-mq.h>
#endif
#endif

/* ============================================================================
 * CONSTANTS AND CONFIGURATION
 * ============================================================================
 */

/** Maximum length for captured filenames (including null terminator) */
#define FILENAME_MAX_LEN 256

/** Length of block operation type string (e.g., "R", "W", "RA") */
#define OP_LEN 8

/* ============================================================================
 * FILESYSTEM MAGIC NUMBERS
 * ============================================================================
 * These magic numbers identify virtual/pseudo filesystems that should be
 * excluded from I/O tracing to reduce noise and focus on real storage I/O.
 * Each filesystem has a unique magic number in its superblock.
 */

#define PROC_SUPER_MAGIC 0x9fa0           /**< /proc filesystem */
#define SYSFS_MAGIC 0x62656572             /**< /sys filesystem */
#define TMPFS_MAGIC 0x01021994             /**< tmpfs (in-memory filesystem) */
#define SOCKFS_MAGIC 0x9fa2                /**< Socket pseudo-filesystem */
#define DEBUGFS_MAGIC 0x64626720           /**< Debug filesystem (/sys/kernel/debug) */
#define DEVPTS_SUPER_MAGIC 0x1cd1          /**< devpts (pseudo-terminal devices) */
#define DEVTMPFS_MAGIC 0x74656d70          /**< devtmpfs (/dev) */
#define PIPEFS_MAGIC 0x50495045            /**< Pipe pseudo-filesystem */
#define CGROUP_SUPER_MAGIC 0x27e0eb        /**< Control group filesystem */
#define SELINUX_MAGIC 0xf97cff8c           /**< SELinux filesystem */
#define NFS_SUPER_MAGIC 0x6969             /**< Network File System */
#define AUTOFS_SUPER_MAGIC 0x0187          /**< Automounter filesystem */
#define MQUEUE_MAGIC 0x19800202            /**< POSIX message queue filesystem */
#define FUSE_SUPER_MAGIC 0x65735546        /**< FUSE filesystem */
#define RAMFS_MAGIC 0x858458f6             /**< RAM filesystem */
#define BINFMTFS_MAGIC 0x42494e4d          /**< Binary format handler filesystem */
#define FUTEXFS_SUPER_MAGIC 0xBAD1DEA      /**< Futex filesystem */
#define EVENTPOLLFS_MAGIC 0x19800202       /**< Event poll filesystem */
#define INOTIFYFS_SUPER_MAGIC 0x2BAD1DEA   /**< Inotify filesystem */
#define AIO_RING_MAGIC 0x19800202          /**< Async I/O ring buffer */
#define XENFS_SUPER_MAGIC 0xabba1974       /**< Xen hypervisor filesystem */
#define RPCAUTH_GSSMAGIC 0x67596969        /**< RPC/GSS authentication */
#define OVERLAYFS_SUPER_MAGIC 0x794c7630   /**< OverlayFS (container layers) */
#define TRACEFS_MAGIC 0x74726163           /**< Tracing filesystem (/sys/kernel/tracing) */

/* ============================================================================
 * OPERATION TYPE ENUMERATIONS
 * ============================================================================
 */

/**
 * @brief VFS operation types for I/O event classification
 *
 * These operation types categorize traced filesystem events for analysis.
 * Each traced VFS function maps to one of these operation types.
 */
enum op_type {
  OP_READ = 1,      /**< vfs_read() - Reading data from a file */
  OP_WRITE,         /**< vfs_write() - Writing data to a file */
  OP_OPEN,          /**< vfs_open() - Opening a file descriptor */
  OP_CLOSE,         /**< fput() - Closing/releasing a file descriptor */
  OP_FSYNC,         /**< vfs_fsync() - Flushing file data to storage */
  OP_MMAP,          /**< mmap_region() - Memory-mapping a file */
  OP_MUNMAP,        /**< vm_munmap() - Unmapping memory region */
  OP_GETATTR,       /**< vfs_getattr() - Getting file attributes (stat) */
  OP_SETATTR,       /**< vfs_setattr() - Setting file attributes (chmod, chown) */
  OP_CHDIR,         /**< sys_chdir() - Changing working directory */
  OP_READDIR,       /**< iterate_dir() - Reading directory entries */
  OP_UNLINK,        /**< vfs_unlink() - Deleting a file */
  OP_TRUNCATE,      /**< vfs_truncate() - Truncating file size */
  OP_SYNC,          /**< ksys_sync() - Syncing all filesystems */
  OP_RENAME,        /**< vfs_rename() - Renaming/moving a file */
  OP_MKDIR,         /**< vfs_mkdir() - Creating a directory */
  OP_RMDIR,         /**< vfs_rmdir() - Removing a directory */
  OP_LINK,          /**< vfs_link() - Creating a hard link */
  OP_SYMLINK,       /**< vfs_symlink() - Creating a symbolic link */
  OP_FALLOCATE,     /**< vfs_fallocate() - Pre-allocating file space */
  OP_SENDFILE,      /**< do_sendfile() - Zero-copy send to socket */
  /* Enhanced operations for advanced I/O tracing */
  OP_SPLICE,        /**< splice() - Zero-copy pipe transfer */
  OP_VMSPLICE,      /**< vmsplice() - Splice user pages to pipe */
  OP_MSYNC,         /**< msync() - Sync memory-mapped region */
  OP_MADVISE,       /**< madvise() - Memory usage advice to kernel */
  OP_DIO_READ,      /**< Direct I/O read (bypassing page cache) */
  OP_DIO_WRITE,     /**< Direct I/O write (bypassing page cache) */
  /* VM lifecycle events */
  OP_MREMAP,        /**< mremap() - Remap/move/resize a memory region */
  OP_PROCESS_EXEC,  /**< sched_process_exec - Process executed new image (address space wiped) */
  OP_PROCESS_EXIT,  /**< sched_process_exit - Process terminated */
  OP_FDATASYNC      /**< fdatasync() - Flush file data to storage (skip metadata unless required) */
};

/* ============================================================================
 * DATA STRUCTURES FOR PERF EVENTS
 * ============================================================================
 * These structures define the event data sent to userspace via perf buffers.
 * Each traced operation populates one of these structs before submission.
 */

/**
 * @brief Primary VFS event data structure
 *
 * Contains all information captured for single-path VFS operations
 * (read, write, open, close, etc.). Sent to userspace via events perf buffer.
 */
struct data_t {
  u32 pid;                        /**< Process ID (PID) of the calling process */
  u64 ts;                         /**< Timestamp in nanoseconds (boot time) */
  char comm[TASK_COMM_LEN];       /**< Process name (16 chars max) */
  char filename[FILENAME_MAX_LEN]; /**< Filename from dentry (basename only) */
  u64 inode;                      /**< Inode number for file identification */
  u64 size;                       /**< Operation size in bytes (read/write length) */
  u64 address;                    /**< Mapping address for MMAP/MUNMAP events */
  u32 flags;                      /**< File flags (O_RDONLY, O_SYNC, etc.) */
  enum op_type op;                /**< Operation type from op_type enum */
  /* Enhanced fields for I/O correlation and analysis */
  u32 fd;                         /**< File descriptor. Populated for OPEN events via the openat kretprobe; 0 for all other event types. */
  u64 offset;                     /**< File offset for read/write operations */
  u32 tid;                        /**< Thread ID for multi-threaded correlation */
  u32 mmap_prot;                  /**< mmap protection flags (PROT_*) for MMAP events */
  u32 mmap_flags;                 /**< mmap mapping flags (MAP_*) for MMAP events */
  u64 old_addr;                   /**< mremap: old mapping start address (0 for other ops) */
  u64 old_size;                   /**< mremap: old mapping length (0 for other ops) */
  /* Completion metadata (populated by the READ/WRITE return probes) */
  s64 ret_val;                    /**< Syscall return value: bytes moved on success, -errno on failure (READ/WRITE) */
  u64 latency_ns;                 /**< Operation duration in ns from entry to return (READ/WRITE) */
  /* Provenance metadata (populated for READ/WRITE/OPEN) */
  u32 dev;                        /**< Backing device id (super_block->s_dev, major:minor encoded) */
  u32 ppid;                       /**< Parent process ID (real_parent->tgid) */
  u64 cgroup_id;                  /**< cgroup v2 id — container identifier */
  u32 fs_magic;                   /**< Superblock magic for filesystem-type classification */
};

/**
 * @brief Dual-path VFS event data structure
 *
 * Used for operations involving two paths (rename, link, symlink).
 * Larger than data_t due to dual filenames, allocated from per-CPU array
 * to avoid exceeding eBPF stack limit (512 bytes).
 */
struct data_dual_t {
  u32 pid;                            /**< Process ID of the calling process */
  u64 ts;                             /**< Timestamp in nanoseconds */
  char comm[TASK_COMM_LEN];           /**< Process name */
  char filename_old[FILENAME_MAX_LEN]; /**< Source/old filename (rename src, link target) */
  char filename_new[FILENAME_MAX_LEN]; /**< Destination/new filename */
  u64 inode_old;                      /**< Source inode number */
  u64 inode_new;                      /**< Destination inode number */
  u32 flags;                          /**< Operation-specific flags */
  enum op_type op;                    /**< Operation type (RENAME, LINK, SYMLINK) */
  u64 latency_ns;                     /**< Operation latency */
};

/**
 * @brief Kernel renamedata structure (kernel 5.12+)
 *
 * Used by vfs_rename() in modern kernels. We define a minimal version
 * to extract the dentry pointers we need.
 */
struct renamedata_bpf {
  void *old_mnt_idmap;
  struct inode *old_dir;
  struct dentry *old_dentry;
  void *new_mnt_idmap;
  struct inode *new_dir;
  struct dentry *new_dentry;
  /* remaining fields not needed */
};

/**
 * @brief Staging struct for sys_mremap arguments
 *
 * Saved by the kprobe entry and consumed by the kretprobe so the
 * return probe can emit an event containing both old and new addresses.
 */
struct mremap_args {
  u64 old_addr;  /**< Old mapping start address */
  u64 old_len;   /**< Old mapping length */
  u64 new_len;   /**< Requested new length */
  u64 flags;     /**< mremap flags (MREMAP_MAYMOVE, etc.) */
};

/**
 * @brief Block layer I/O event data structure
 *
 * Captures block device I/O requests with latency tracking.
 * Tracks the complete lifecycle: insert -> issue -> complete.
 */
struct block_event {
  u64 ts;                   /**< Completion timestamp in nanoseconds */
  u32 pid;                  /**< Process ID that submitted the request */
  char comm[TASK_COMM_LEN]; /**< Process name */
  u64 sector;               /**< Starting sector number on disk */
  char op[OP_LEN];          /**< Operation type string ("R", "W", "RA", "WS") */
  u32 tid;                  /**< Thread ID */
  u32 cpu_id;               /**< CPU where completion was processed */
  u32 ppid;                 /**< Parent process ID */
  u32 cmd_flags;            /**< Request command flags (REQ_SYNC, REQ_META, etc.) */
  u64 bio_size;             /**< I/O size in bytes (sectors * 512) */
  u64 latency_ns;           /**< Time from issue to completion (device latency) */
  u32 dev;                  /**< Device number (major:minor encoded) for partition ID */
  u64 queue_time_ns;        /**< Time from insert to issue (scheduler latency) */
  u32 op_code;              /**< Raw block operation code (REQ_OP_*) */
};

/* ============================================================================
 * PAGE FAULT TRACING STRUCTURES
 * ============================================================================
 * Tracks memory-mapped file I/O by monitoring page faults that trigger
 * actual disk reads (major faults) or page cache access (minor faults).
 */

/** @brief Page fault access type */
enum pagefault_type {
  FAULT_READ = 0,   /**< Read access triggered the fault */
  FAULT_WRITE = 1   /**< Write access triggered the fault */
};

/**
 * @brief Page fault event data structure
 *
 * Captures file-backed page faults that occur when accessing
 * memory-mapped files. Major faults indicate actual disk I/O.
 */
struct pagefault_data {
  u64 ts;                   /**< Timestamp in nanoseconds */
  u32 pid;                  /**< Process ID */
  u32 tid;                  /**< Thread ID */
  char comm[TASK_COMM_LEN]; /**< Process name */
  u64 address;              /**< Faulting virtual address */
  u64 inode;                /**< Backing file inode (0 if anonymous mapping) */
  u64 offset;               /**< File offset in pages (pgoff) */
  u8 fault_type;            /**< FAULT_READ or FAULT_WRITE */
  u8 major;                 /**< 0=minor (cached), 1=major (disk read) */
  u32 dev_id;               /**< Device ID from file's superblock */
};

/* ============================================================================
 * PAGE CACHE TRACING STRUCTURES
 * ============================================================================
 * The page cache buffers disk I/O in memory. These structures track
 * cache efficacy: hits reduce disk reads, misses cause disk I/O.
 */

/**
 * @brief Page cache event types
 *
 * Categorizes page cache lifecycle events from allocation to eviction.
 */
enum cache_event_type {
  CACHE_HIT = 0,            /**< Page found in cache (no disk I/O) */
  CACHE_MISS = 1,           /**< Page not in cache (disk read required) */
  CACHE_DIRTY = 2,          /**< Page marked dirty (modified, needs writeback) */
  CACHE_WRITEBACK_START = 3, /**< Dirty page writeback initiated */
  CACHE_WRITEBACK_END = 4,  /**< Dirty page writeback completed */
  CACHE_EVICT = 5,          /**< Page evicted from cache (memory pressure) */
  CACHE_INVALIDATE = 6,     /**< Pages explicitly invalidated (truncate, drop) */
  CACHE_DROP = 7,           /**< Page dropped via invalidation */
  CACHE_READAHEAD = 8,      /**< Prefetch/readahead pages loaded */
  CACHE_RECLAIM = 9,        /**< Memory reclaim event (kswapd/direct) */
};

/**
 * @brief Page cache event data structure
 *
 * Contains metadata about page cache operations for analysis
 * of cache hit rates, writeback patterns, and memory pressure.
 */
struct cache_data {
  u64 ts;                   /**< Timestamp in nanoseconds */
  u32 pid;                  /**< Process ID that triggered the event */
  u8 type;                  /**< Event type from cache_event_type enum */
  char comm[TASK_COMM_LEN]; /**< Process name */
  u64 inode;                /**< File inode number */
  u64 index;                /**< Page index (file offset / PAGE_SIZE) */
  u32 size;                 /**< File size in pages (populated by helper) */
  u32 cpu_id;               /**< CPU where event occurred */
  u32 dev_id;               /**< Device ID from superblock */
  u32 count;                /**< Number of pages (for batch operations) */
};

/* ============================================================================
 * IO_URING TRACING STRUCTURES
 * ============================================================================
 * Structures for tracing io_uring async I/O operations including:
 * - Ring setup and syscall entry (ENTER)
 * - SQE submission (SUBMIT)
 * - Request completion (COMPLETE)
 * - Async worker execution (WORKER)
 */

/** @brief io_uring event types */
enum io_uring_event_type {
  IOURING_ENTER    = 0,  /**< io_uring_enter syscall */
  IOURING_SUBMIT   = 1,  /**< Individual SQE submission */
  IOURING_COMPLETE = 2,  /**< Request completed */
  IOURING_WORKER   = 3   /**< Request executed by io-wq worker */
};

/** @brief io_uring opcode names (subset of common operations) */
enum io_uring_op {
  IORING_OP_NOP = 0,
  IORING_OP_READV = 1,
  IORING_OP_WRITEV = 2,
  IORING_OP_FSYNC = 3,
  IORING_OP_READ_FIXED = 4,
  IORING_OP_WRITE_FIXED = 5,
  IORING_OP_POLL_ADD = 6,
  IORING_OP_POLL_REMOVE = 7,
  IORING_OP_SYNC_FILE_RANGE = 8,
  IORING_OP_SENDMSG = 9,
  IORING_OP_RECVMSG = 10,
  IORING_OP_TIMEOUT = 11,
  IORING_OP_TIMEOUT_REMOVE = 12,
  IORING_OP_ACCEPT = 13,
  IORING_OP_ASYNC_CANCEL = 14,
  IORING_OP_LINK_TIMEOUT = 15,
  IORING_OP_CONNECT = 16,
  IORING_OP_FALLOCATE = 17,
  IORING_OP_OPENAT = 18,
  IORING_OP_CLOSE = 19,
  IORING_OP_FILES_UPDATE = 20,
  IORING_OP_STATX = 21,
  IORING_OP_READ = 22,
  IORING_OP_WRITE = 23,
  IORING_OP_FADVISE = 24,
  IORING_OP_MADVISE = 25,
  IORING_OP_SEND = 26,
  IORING_OP_RECV = 27,
  IORING_OP_OPENAT2 = 28,
  IORING_OP_EPOLL_CTL = 29,
  IORING_OP_SPLICE = 30,
  IORING_OP_PROVIDE_BUFFERS = 31,
  IORING_OP_REMOVE_BUFFERS = 32,
  IORING_OP_TEE = 33,
  IORING_OP_SHUTDOWN = 34,
  IORING_OP_RENAMEAT = 35,
  IORING_OP_UNLINKAT = 36,
  IORING_OP_MKDIRAT = 37,
  IORING_OP_SYMLINKAT = 38,
  IORING_OP_LINKAT = 39,
};

/**
 * @brief io_uring event data structure (unified schema)
 *
 * Contains all fields for io_uring event tracing. Unused fields
 * remain zero depending on event_type.
 */
struct io_uring_event_data {
  u64 timestamp_ns;             /**< Event timestamp in nanoseconds */
  u8 event_type;                /**< io_uring_event_type enum */
  u32 pid;                      /**< Process ID */
  u32 tid;                      /**< Thread ID */
  char comm[TASK_COMM_LEN];     /**< Process name */
  u32 cpu;                      /**< CPU where event occurred */
  
  /* Syscall layer fields (ENTER event) */
  u32 ring_fd;                  /**< io_uring file descriptor */
  u64 ring_ptr;                 /**< struct io_ring_ctx pointer */
  u32 to_submit;                /**< Number of SQEs to submit */
  u32 min_complete;             /**< Minimum completions to wait for */
  u32 enter_flags;              /**< io_uring_enter flags */
  
  /* SQE submission fields (SUBMIT event) */
  u64 req_ptr;                  /**< struct io_kiocb pointer (correlation key) */
  u64 user_data;                /**< User-provided data for correlation */
  u8 opcode;                    /**< io_uring operation code */
  s32 fd;                       /**< Target file descriptor */
  u32 len;                      /**< I/O length in bytes */
  u64 offset;                   /**< File offset */
  u8 sqe_flags;                 /**< SQE flags (IOSQE_*) */
  u16 ioprio;                   /**< I/O priority */
  u16 buf_index;                /**< Buffer index for fixed buffers */
  u16 personality;              /**< Personality ID */
  
  /* Completion fields (COMPLETE event) */
  s32 result;                   /**< Operation result (bytes or -errno) */
  u8 is_error;                  /**< 1 if result < 0 */
  s32 cqe_errno;                /**< Errno if error (positive value) */
  
  /* Latency tracking */
  u64 submit_ts_ns;             /**< Submission timestamp */
  u64 complete_ts_ns;           /**< Completion timestamp */
  u64 latency_ns;               /**< Complete - submit latency */
  
  /* Worker fields (WORKER event) */
  u32 worker_pid;               /**< io-wq worker PID */
  u32 worker_tid;               /**< io-wq worker TID */
  u32 worker_cpu;               /**< io-wq worker CPU */
  u8 is_async;                  /**< 1 if executed by io-wq worker */
  
  /* File correlation — populated for file-backed ops from req->file so that
   * io_uring I/O can be joined with the fs/VFS trace by inode/device. */
  u64 inode;                    /**< Backing file inode (0 if not a file op) */
  u32 dev;                      /**< Backing device id (super_block->s_dev) */
  u32 fs_magic;                 /**< Superblock magic for fs-type classification */

  /* Ring state (optional) */
  u32 sq_head;
  u32 sq_tail;
  u32 cq_head;
  u32 cq_tail;
  u32 sq_depth;                 /**< sq_tail - sq_head */
  u32 cq_depth;                 /**< cq_tail - cq_head */
};

/** @brief Context for tracking io_uring request submission time */
struct io_uring_submit_ctx {
  u64 submit_ts_ns;           /**< Submission timestamp */
  u64 user_data;              /**< User data for correlation */
  u8 opcode;                  /**< Operation code */
  s32 fd;                     /**< Target FD */
  u32 len;                    /**< I/O length */
  u64 offset;                 /**< File offset */
  u8 sqe_flags;               /**< SQE flags (IOSQE_*) */
  u16 ioprio;                 /**< I/O priority */
  u16 buf_index;              /**< Fixed-buffer index */
  u64 inode;                  /**< Backing file inode (file ops) */
  u32 dev;                    /**< Backing device id */
  u32 fs_magic;               /**< Superblock magic */
};

/**
 * @brief VFS operation context for latency tracking
 *
 * Stores entry context for VFS operations that need return probe correlation.
 */
struct vfs_info {
  u64 start_ts;       /**< Entry timestamp for latency calculation */
  struct file *file;  /**< File pointer captured at entry */
  size_t size;        /**< Requested operation size */
  loff_t *pos;        /**< File position pointer */
  enum op_type op;    /**< Operation type for return probe */
};

/* ============================================================================
 * BPF MAPS
 * ============================================================================
 * BPF maps store state and configuration. Hash maps allow O(1) lookup,
 * per-CPU arrays avoid lock contention, perf buffers stream events.
 */

/**
 * @brief Submitter context captured at block_rq_issue time.
 *
 * block_rq_complete runs in IRQ/softirq context, where the current task is
 * whatever happened to be running (frequently swapper/N), NOT the process
 * that submitted the I/O. Attribution must therefore be captured at issue
 * time and carried to the completion event via this struct.
 */
struct block_issue_ctx {
  u64 ts;                   /**< Issue timestamp (device latency baseline) */
  u32 pid;                  /**< Submitting process ID */
  u32 tid;                  /**< Submitting thread ID */
  u32 ppid;                 /**< Submitter's parent PID */
  char comm[TASK_COMM_LEN]; /**< Submitting process name */
};

/**
 * @brief Collision-free correlation key for block requests.
 *
 * dev and sector are kept as separate fields (not folded into one u64) so
 * distinct (dev, sector) pairs can never collide. Built exclusively via
 * block_rq_key() (see the block tracepoint section), which zeroes the
 * padding — hash map key comparison covers every byte.
 */
struct block_rq_key_t {
  u32 dev;     /**< Device number (major:minor encoded) */
  u32 pad;     /**< Explicit padding — always zero */
  u64 sector;  /**< Full 64-bit starting sector */
};

/* Block layer latency tracking maps. LRU so that requests that never
 * complete (e.g. merged into another request) cannot permanently fill the
 * map and starve later requests. */
BPF_TABLE("lru_hash", struct block_rq_key_t, struct block_issue_ctx, block_start_times, 10240); /**< Issue time + submitter, keyed by dev+sector */
BPF_TABLE("lru_hash", struct block_rq_key_t, u64, block_insert_times, 10240);  /**< Tracks block request insert time (queue latency) */

/* Configuration map - stores tracer PID to exclude self-tracing */
BPF_HASH(tracer_config, u32, u32, 1);    /**< Key 0 = tracer PID to exclude */

/* Direct I/O direction staged at entry (1 = write), consumed by the
 * iomap_dio_rw/__blockdev_direct_IO kretprobe. */
BPF_HASH(dio_staging, u64, u8, 10240);

/* vfs_fsync entry timestamp, used by trace_vfs_fsync_range to suppress the
 * duplicate event for the nested vfs_fsync -> vfs_fsync_range call. */
BPF_HASH(fsync_inflight, u64, u64, 10240);

/* io_uring request tracking map. LRU because completions that bypass the
 * probed completion path (batched completions on modern kernels) would
 * otherwise leak entries until the map is permanently full. */
BPF_TABLE("lru_hash", u64, struct io_uring_submit_ctx, io_uring_submit_map, 65536); /**< Track submissions by req_ptr */

/* Per-CPU buffer for large structs that exceed 512-byte stack limit */
BPF_PERCPU_ARRAY(dual_data_buffer, struct data_dual_t, 1);

/**
 * @brief Stores the user-provided path string from do_sys_openat2 entry.
 *
 * Keyed by pid_tgid. Written by trace_do_sys_openat2_entry and consumed
 * by trace_vfs_open to provide the full absolute path (as given by the
 * caller) in place of the d_name basename.
 */
struct open_path_t {
  char path[FILENAME_MAX_LEN]; /**< User-space path string from openat args */
};

/* Staged path from trace_do_sys_openat2_entry, consumed by trace_vfs_open */
BPF_HASH(open_path_staging, u64, struct open_path_t, 4096);

/* Staged event data from trace_vfs_open, completed by trace_sys_openat_ret */
BPF_HASH(open_staging, u64, struct data_t, 4096);

/* Staged MMAP event from do_mmap entry, completed by the do_mmap kretprobe. */
BPF_HASH(mmap_staging, u64, struct data_t, 4096);

/* Staged READ/WRITE event from the vfs_read/vfs_write entry probe, completed by
 * the matching kretprobe which fills in the return value and latency. */
BPF_HASH(rw_staging, u64, struct data_t, 10240);

/* Staged mremap args from sys_mremap entry, consumed by the kretprobe. */
BPF_HASH(mremap_staging, u64, struct mremap_args, 4096);

/* ============================================================================
 * PERF OUTPUT BUFFERS
 * ============================================================================
 * Perf buffers stream event data to userspace with minimal overhead.
 * Each buffer type corresponds to a specific event category.
 */

BPF_PERF_OUTPUT(events);            /**< VFS single-path events (data_t) */
BPF_PERF_OUTPUT(events_dual);       /**< VFS dual-path events (data_dual_t) */
BPF_PERF_OUTPUT(bl_events);         /**< Block layer events (block_event) */
BPF_PERF_OUTPUT(cache_events);      /**< Page cache events (cache_data) */
BPF_PERF_OUTPUT(pagefault_events);  /**< Memory-mapped page faults (pagefault_data) */
BPF_PERF_OUTPUT(io_uring_events);   /**< io_uring events (io_uring_event_data) */

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================
 * Static inline helpers for common operations. __always_inline ensures
 * these are inlined to avoid BPF function call overhead.
 */

/**
 * @brief Get inode number from a file structure
 *
 * Safely traverses file->f_path.dentry->d_inode->i_ino
 *
 * @param file  Kernel file structure pointer
 * @return      Inode number, or 0 if unavailable
 */
static u64 get_file_inode(struct file *file) {
  u64 inode = 0;
  if (file && file->f_path.dentry && file->f_path.dentry->d_inode) {
    inode = file->f_path.dentry->d_inode->i_ino;
  }
  return inode;
}

/**
 * @brief Get the parent process ID (tgid of real_parent) of the current task.
 *
 * @return Parent PID, or 0 if it cannot be read.
 */
static __always_inline u32 get_ppid(void) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct task_struct *parent = NULL;
  u32 ppid = 0;
  if (task) {
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
      bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);
    }
  }
  return ppid;
}

/**
 * @brief Read the backing device id and filesystem magic from a file's
 *        superblock, used to record the mount/device and to classify the
 *        filesystem source (physical vs network vs overlay, etc.).
 *
 * @param file     Kernel file structure
 * @param dev      Out: super_block->s_dev (major:minor encoded); untouched on failure
 * @param fs_magic Out: super_block->s_magic; untouched on failure
 */
static __always_inline void get_file_source(struct file *file, u32 *dev,
                                            u32 *fs_magic) {
  if (!file || !dev || !fs_magic) return;
  struct dentry *dentry = NULL;
  bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
  if (!dentry) return;
  struct super_block *sb = NULL;
  bpf_probe_read_kernel(&sb, sizeof(sb), &dentry->d_sb);
  if (!sb) return;
  bpf_probe_read_kernel(dev, sizeof(*dev), &sb->s_dev);
  unsigned long magic = 0;
  bpf_probe_read_kernel(&magic, sizeof(magic), &sb->s_magic);
  *fs_magic = (u32)magic;
}

/**
 * @brief Check if a file is a regular file (not virtual/pseudo filesystem)
 *
 * Filters out pseudo-filesystems (proc, sys, devtmpfs, etc.) to focus
 * tracing on real storage I/O. Uses filesystem magic numbers for detection.
 *
 * @param file  Kernel file structure pointer
 * @return      true if regular file on real filesystem, false otherwise
 */
static bool is_regular_file(struct file *file) {
  bool is_reg, is_virtual;
  if (!file || !file->f_path.dentry || !file->f_path.dentry->d_inode ||
      !file->f_path.dentry->d_sb) {
    return false;
  }
  umode_t mode;
  bpf_probe_read_kernel(&mode, sizeof(mode),
                        &file->f_path.dentry->d_inode->i_mode);
  is_reg = S_ISREG(mode);  /* Check if regular file (not dir/socket/pipe) */

  struct super_block *sb = file->f_path.dentry->d_sb;
  unsigned long magic = 0;
  bpf_probe_read_kernel(&magic, sizeof(magic), &sb->s_magic);

  switch (magic) {
  case PROC_SUPER_MAGIC:
  case SYSFS_MAGIC:
  case TMPFS_MAGIC:
  case SOCKFS_MAGIC:
  case DEBUGFS_MAGIC:
  case DEVPTS_SUPER_MAGIC:
  case DEVTMPFS_MAGIC:
  case PIPEFS_MAGIC:
  case CGROUP_SUPER_MAGIC:
  case SELINUX_MAGIC:
  case FUTEXFS_SUPER_MAGIC:
  case INOTIFYFS_SUPER_MAGIC:
  case XENFS_SUPER_MAGIC:
  case RPCAUTH_GSSMAGIC:
  case TRACEFS_MAGIC:
  case 0x19800202:
    is_virtual = true;
    break;
  default:
    is_virtual = false;
  }

  return !is_virtual && is_reg;
}

static bool is_regular_file_from_path(const struct path *path) {
  struct dentry *d = NULL;
  bpf_probe_read_kernel(&d, sizeof(d), &path->dentry);
  if (!d) return false;

  struct inode *inode = NULL;
  bpf_probe_read_kernel(&inode, sizeof(inode), &d->d_inode);
  if (!inode) return false;

  umode_t mode = 0;
  bpf_probe_read_kernel(&mode, sizeof(mode), &inode->i_mode);
  if (!S_ISREG(mode)) return false;

  struct super_block *sb = NULL;
  bpf_probe_read_kernel(&sb, sizeof(sb), &d->d_sb);
  if (!sb) return false;

  unsigned long magic = 0;
  bpf_probe_read_kernel(&magic, sizeof(magic), &sb->s_magic);

  switch (magic) {
  case PROC_SUPER_MAGIC:
  case SYSFS_MAGIC:
  case TMPFS_MAGIC:
  case SOCKFS_MAGIC:
  case DEBUGFS_MAGIC:
  case DEVPTS_SUPER_MAGIC:
  case DEVTMPFS_MAGIC:
  case PIPEFS_MAGIC:
  case CGROUP_SUPER_MAGIC:
  case SELINUX_MAGIC:
  case FUTEXFS_SUPER_MAGIC:
  case INOTIFYFS_SUPER_MAGIC:
  case XENFS_SUPER_MAGIC:
  case RPCAUTH_GSSMAGIC:
  case TRACEFS_MAGIC:
  case 0x19800202:
    return false;
  default:
    return true;
  }
}

/**
 * @brief Extract filename from file structure
 *
 * Gets the basename (not full path) from the file's dentry.
 * Full path reconstruction requires expensive dentry walking.
 *
 * @param file  Kernel file structure
 * @param buf   Output buffer for filename
 * @param size  Buffer size
 * @return      0 on success
 */
static int get_file_path(struct file *file, char *buf, int size) {
  struct dentry *dentry;

  // Safety check for file pointer
  if (!file) {
    // Mark as anonymous or pipe
    __builtin_memcpy(buf, "", 1);
    return 0;
  }

  dentry = file->f_path.dentry;
  if (!dentry) {
    __builtin_memcpy(buf, "", 1);
    return 0;
  }

  struct super_block *sb = dentry->d_sb;
  unsigned long magic = 0;
  if (sb) {
    bpf_probe_read_kernel(&magic, sizeof(magic), &sb->s_magic);
  }

  const unsigned char *name_ptr;
  bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);

  if (name_ptr) {
    ssize_t len = bpf_probe_read_kernel_str(buf, size, name_ptr);
    volatile char first_char = buf[0];
    if (len <= 0 || first_char == '\0') {
      __builtin_memcpy(buf, "", 1);
    }
  } else {
    __builtin_memcpy(buf, "", 1);
  }

  return 0;
}

/**
 * @brief Get inode number from a dentry structure
 *
 * @param dentry  Kernel dentry structure
 * @return        Inode number, or 0 if unavailable
 */
static u64 get_file_inode_from_dentry(struct dentry *dentry) {
  u64 inode = 0;
  if (!dentry)
    return 0;
  // dentry may be a scalar (loaded via bpf_probe_read_kernel), so all
  // further dereferences must go through bpf_probe_read_kernel.
  struct inode *d_inode = NULL;
  bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
  if (d_inode)
    bpf_probe_read_kernel(&inode, sizeof(inode), &d_inode->i_ino);
  return inode;
}

/**
 * @brief Extract filename from dentry structure
 *
 * Gets the filename component from a dentry's d_name.
 *
 * @param dentry  Kernel dentry structure
 * @param buf     Output buffer for filename
 * @param size    Buffer size
 * @return        0 on success
 */
static int get_file_path_from_dentry(struct dentry *dentry, char *buf,
                                     int size) {
  if (!dentry) {
    buf[0] = '\0';  // Empty string if dentry unavailable
    return 0;
  }

  // dentry may be a scalar (loaded via bpf_probe_read_kernel), so all
  // further dereferences must go through bpf_probe_read_kernel.
  const unsigned char *name_ptr = NULL;
  bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);

  if (name_ptr) {
    bpf_probe_read_kernel_str(buf, size, name_ptr);
  } else {
    buf[0] = '\0';
  }

  return 0;
}

/**
 * @brief Populate cache event metadata from inode
 *
 * Extracts file size (in pages), device ID, and sets default count.
 *
 * @note Filename cannot be reliably resolved from inode alone in eBPF
 *       because inode->i_dentry is a list requiring complex iteration.
 *       The filename field must be populated before calling if needed.
 *
 * @param data   Cache event structure to populate
 * @param inode  Kernel inode structure
 */
static void populate_cache_metadata(struct cache_data *data, struct inode *inode) {
  if (!inode || !data) {
    return;
  }
  
  // Try to get file size in pages
  loff_t file_size = 0;
  bpf_probe_read_kernel(&file_size, sizeof(file_size), &inode->i_size);
  data->size = (u32)(file_size >> PAGE_SHIFT);  // Convert bytes to number of pages
  
  // Get device ID from superblock
  struct super_block *sb = NULL;
  bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb);
  if (sb) {
    bpf_probe_read_kernel(&data->dev_id, sizeof(data->dev_id), &sb->s_dev);
  }
  
  // Set count to 1 for single-page operations if not already set
  if (data->count == 0) {
    data->count = 1;
  }
}

/* ============================================================================
 * VFS OPERATION PROBES
 * ============================================================================
 * These kprobes attach to VFS (Virtual File System) layer functions to
 * capture file I/O operations at the filesystem-agnostic layer.
 */

/**
 * @brief Trace vfs_read() - VFS read operations
 *
 * Captures file read operations including offset and size.
 * Filters out virtual filesystems and tracer's own PID.
 *
 * @param ctx   BPF context with registers
 * @param file  File being read
 * @param buf   Userspace buffer (not used)
 * @param count Bytes to read
 * @param pos   File position pointer
 * @return      0 (continue execution)
 */
int trace_vfs_read(struct pt_regs *ctx, struct file *file, char __user *buf,
                   size_t count, loff_t *pos) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file(file)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_READ;
  data.inode = get_file_inode(file);
  data.size = count;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);
  
  // Capture file offset
  if (pos) {
    bpf_probe_read_kernel(&data.offset, sizeof(data.offset), pos);
  }
  
  // FD is not directly available from struct file in kernel context
  // We capture 0 to indicate it needs user-space correlation
  data.fd = 0;

  // Provenance metadata: parent PID, container (cgroup) id, backing
  // device, and filesystem magic for source classification.
  data.ppid = get_ppid();
  data.cgroup_id = bpf_get_current_cgroup_id();
  get_file_source(file, &data.dev, &data.fs_magic);

  // Defer submission to the kretprobe, which records the return value
  // (bytes read or negative errno) and the operation latency.
  rw_staging.update(&pid_tgid, &data);

  return 0;
}

/**
 * @brief Trace vfs_read() return — record bytes read / errno and latency.
 *
 * Completes the event staged by trace_vfs_read() with the syscall return
 * value and the entry-to-return duration, then submits it.
 *
 * @param ctx  BPF context (return value via PT_REGS_RC)
 * @return     0
 */
int trace_vfs_read_ret(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct data_t *data = rw_staging.lookup(&pid_tgid);
  if (!data) {
    return 0;
  }
  long ret = PT_REGS_RC(ctx);
  data->ret_val = (s64)ret;
  data->latency_ns = bpf_ktime_get_ns() - data->ts;
  events.perf_submit(ctx, data, sizeof(*data));
  rw_staging.delete(&pid_tgid);
  return 0;
}

/**
 * @brief Trace vfs_write() - VFS write operations
 *
 * Captures file write operations with offset tracking.
 *
 * @param ctx   BPF context
 * @param file  File being written
 * @param buf   Userspace data buffer (not accessed)
 * @param count Bytes to write
 * @param pos   File position pointer
 * @return      0
 */
int trace_vfs_write(struct pt_regs *ctx, struct file *file,
                    const char __user *buf, size_t count, loff_t *pos) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file(file)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_WRITE;
  data.inode = get_file_inode(file);
  data.size = count;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);
  
  // Capture file offset
  if (pos) {
    bpf_probe_read_kernel(&data.offset, sizeof(data.offset), pos);
  }

  data.fd = 0;

  // Provenance metadata: parent PID, container (cgroup) id, backing
  // device, and filesystem magic for source classification.
  data.ppid = get_ppid();
  data.cgroup_id = bpf_get_current_cgroup_id();
  get_file_source(file, &data.dev, &data.fs_magic);

  // Defer submission to the kretprobe, which records the return value
  // (bytes written or negative errno) and the operation latency.
  rw_staging.update(&pid_tgid, &data);

  return 0;
}

/**
 * @brief Trace vfs_write() return — record bytes written / errno and latency.
 *
 * Completes the event staged by trace_vfs_write() with the syscall return
 * value and the entry-to-return duration, then submits it.
 *
 * @param ctx  BPF context (return value via PT_REGS_RC)
 * @return     0
 */
int trace_vfs_write_ret(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct data_t *data = rw_staging.lookup(&pid_tgid);
  if (!data) {
    return 0;
  }
  long ret = PT_REGS_RC(ctx);
  data->ret_val = (s64)ret;
  data->latency_ns = bpf_ktime_get_ns() - data->ts;
  events.perf_submit(ctx, data, sizeof(*data));
  rw_staging.delete(&pid_tgid);
  return 0;
}

/**
 * @brief Trace vfs_open() - VFS file open operations
 *
 * Captures file opens with flags (O_RDONLY, O_WRONLY, O_SYNC, etc.).
 * Does not filter by file type to catch all opens.
 *
 * @param ctx   BPF context
 * @param path  Path being opened
 * @param file  Newly allocated file structure
 * @return      0
 */
/**
 * @brief Kprobe on do_sys_openat2 entry — captures the user-provided path.
 *
 * Reads the filename string from the second syscall argument with
 * bpf_probe_read_user_str before the path is resolved by the kernel. This
 * gives us the exact string the caller passed (often an absolute path like
 * "/etc/ld.so.cache") keyed by pid_tgid so that trace_vfs_open can use it.
 *
 * do_sys_openat2 signature: long do_sys_openat2(int dfd, const char __user *filename, ...)
 *
 * @param ctx  BPF context (PT_REGS_PARM2 = user filename pointer)
 * @return     0
 */
int trace_do_sys_openat2_entry(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  const char __user *user_path = (const char __user *)PT_REGS_PARM2(ctx);
  if (!user_path) {
    return 0;
  }

  struct open_path_t staged = {};
  bpf_probe_read_user_str(staged.path, sizeof(staged.path), user_path);
  open_path_staging.update(&pid_tgid, &staged);
  return 0;
}

#if defined(__x86_64__)
/**
 * @brief Kprobe entry for the __x64_sys_openat syscall wrapper.
 *
 * __x64_sys_* wrappers receive the user pt_regs as their only argument
 * (see trace_mremap_entry_x64); the filename pointer is the second syscall
 * argument, i.e. uregs->si — not PT_REGS_PARM2 of the probe context.
 *
 * @param ctx  BPF context (PARM1 = user pt_regs)
 * @return     0
 */
int trace_openat_entry_x64(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct pt_regs *uregs = (struct pt_regs *)PT_REGS_PARM1(ctx);
  if (!uregs) {
    return 0;
  }

  unsigned long filename_arg = 0;
  bpf_probe_read_kernel(&filename_arg, sizeof(filename_arg), &uregs->si);
  const char __user *user_path = (const char __user *)filename_arg;
  if (!user_path) {
    return 0;
  }

  struct open_path_t staged = {};
  bpf_probe_read_user_str(staged.path, sizeof(staged.path), user_path);
  open_path_staging.update(&pid_tgid, &staged);
  return 0;
}
#endif /* __x86_64__ */

/**
 * @brief Trace vfs_open()
 *
 * Stages a partial data_t for the OPEN event. Uses the absolute path captured
 * by trace_do_sys_openat2_entry when available (most library/file opens), or
 * falls back to the d_name basename from the dentry.
 *
 * Does not filter by file type to catch all opens.
 *
 * @param ctx   BPF context
 * @param path  Path being opened
 * @param file  Newly allocated file structure
 * @return      0
 */
int trace_vfs_open(struct pt_regs *ctx, const struct path *path,
                   struct file *file) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file_from_path(path)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_OPEN;
  data.size = 0;
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);

  // Provenance metadata: parent PID, container (cgroup) id, backing
  // device, and filesystem magic for source classification.
  data.ppid = get_ppid();
  data.cgroup_id = bpf_get_current_cgroup_id();
  get_file_source(file, &data.dev, &data.fs_magic);

  // Prefer the full path captured from the syscall entry (trace_do_sys_openat2_entry).
  // This is the string the caller passed — for library loads and most file opens
  // this is already an absolute path (e.g. /etc/ld.so.cache, /lib/x86_64-linux-gnu/libc.so.6).
  // Fall back to d_name (basename) for opens that don't come through openat
  // (e.g. exec paths, kernel-internal opens).
  struct open_path_t *staged_path = open_path_staging.lookup(&pid_tgid);
  if (staged_path && staged_path->path[0] == '/') {
    bpf_probe_read_kernel(data.filename, sizeof(data.filename), staged_path->path);
  } else {
    // Fallback: read d_name (basename) from the dentry
    struct dentry *path_dentry = NULL;
    bpf_probe_read_kernel(&path_dentry, sizeof(path_dentry), &path->dentry);
    if (path_dentry) {
      const unsigned char *name_ptr = NULL;
      bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &path_dentry->d_name.name);
      if (name_ptr) {
        bpf_probe_read_kernel_str(data.filename, sizeof(data.filename), name_ptr);
      }
    }
  }

  // Inode: path->dentry->d_inode->i_ino
  struct dentry *path_dentry = NULL;
  bpf_probe_read_kernel(&path_dentry, sizeof(path_dentry), &path->dentry);
  if (path_dentry) {
    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &path_dentry->d_inode);
    if (d_inode) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &d_inode->i_ino);
    }
  }

  // Stage the event — the fd is not yet allocated at vfs_open() time.
  // trace_sys_openat_ret (kretprobe on the openat syscall) will pick this
  // up, insert the real fd from the return value, and submit to perf.
  open_staging.update(&pid_tgid, &data);

  return 0;
}

/**
 * @brief Kretprobe on openat syscall — completes the staged OPEN event.
 *
 * Retrieves the partial data_t staged by trace_vfs_open, inserts the
 * file descriptor from PT_REGS_RC (the syscall return value), and submits
 * the completed event to the perf buffer.
 *
 * Attached to do_sys_openat2 (primary, kernel 5.6+) with fallback to
 * __x64_sys_openat / sys_openat in KernelProbeTracker.
 *
 * Failed opens (negative return) are silently discarded.
 *
 * @param ctx  BPF context (return value accessible via PT_REGS_RC)
 * @return     0
 */
int trace_sys_openat_ret(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct data_t *staged = open_staging.lookup(&pid_tgid);
  if (!staged) {
    open_path_staging.delete(&pid_tgid);
    return 0;  // no staged open for this thread (e.g. exec path)
  }

  long fd = PT_REGS_RC(ctx);
  if (fd < 0) {
    // Open failed — discard the staged event cleanly
    open_staging.delete(&pid_tgid);
    open_path_staging.delete(&pid_tgid);
    return 0;
  }

  staged->fd = (u32)fd;
  events.perf_submit(ctx, staged, sizeof(*staged));
  open_staging.delete(&pid_tgid);
  open_path_staging.delete(&pid_tgid);
  return 0;
}

/**
 * @brief Trace vfs_fsync() - File synchronization
 *
 * Captures fsync/fdatasync calls that flush data to storage.
 * datasync flag distinguishes fsync (0) from fdatasync (1).
 *
 * @param ctx      BPF context
 * @param file     File being synced
 * @param datasync 0 for fsync, 1 for fdatasync
 * @return         0
 */
int trace_vfs_fsync(struct pt_regs *ctx, struct file *file, int datasync) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file(file)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = datasync ? OP_FDATASYNC : OP_FSYNC;
  data.inode = get_file_inode(file);
  data.size = 0;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);

  // vfs_fsync() is implemented as vfs_fsync_range(file, 0, LLONG_MAX,
  // datasync); mark this thread so the vfs_fsync_range probe does not emit a
  // second event for the same syscall. Cleared by the vfs_fsync kretprobe.
  fsync_inflight.update(&pid_tgid, &data.ts);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief vfs_fsync() kretprobe — clears the nested-call suppression marker.
 */
int trace_vfs_fsync_ret(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  fsync_inflight.delete(&pid_tgid);
  return 0;
}

/**
 * @brief Trace vfs_fsync_range() - Range-based file synchronization
 *
 * Captures sync_file_range() calls with byte offset range.
 * Size field contains the range size being synced.
 *
 * @param ctx      BPF context
 * @param file     File being synced
 * @param start    Start offset in bytes
 * @param end      End offset (LLONG_MAX means to EOF)
 * @param datasync Sync type flag
 * @return         0
 */
int trace_vfs_fsync_range(struct pt_regs *ctx, struct file *file, loff_t start,
                          loff_t end, int datasync) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file(file)) {
    return 0;
  }

  // Suppress the nested call from vfs_fsync(), which already emitted this
  // event. Entries older than 1s are stale (missed kretprobe) and ignored so
  // a single miss cannot permanently mute this thread's range events.
  u64 *fsync_entry_ts = fsync_inflight.lookup(&pid_tgid);
  if (fsync_entry_ts) {
    if (bpf_ktime_get_ns() - *fsync_entry_ts < 1000000000ULL) {
      return 0;
    }
    fsync_inflight.delete(&pid_tgid);
  }

  loff_t range_size;
  loff_t file_size = 0;
  if (file && file->f_inode) {
    bpf_probe_read_kernel(&file_size, sizeof(file_size),
                          &file->f_inode->i_size);
  }

  if (end == LLONG_MAX) {
    range_size = file_size - start;
  } else {
    range_size = end - start;
  }

  struct data_t data = {};
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = datasync ? OP_FDATASYNC : OP_FSYNC;
  data.inode = get_file_inode(file);
  data.size = range_size;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace fput() - File descriptor close/release
 *
 * Captures when file descriptors are released (reference count drops).
 * This is the actual close, not close() syscall entry.
 *
 * @param ctx   BPF context
 * @param file  File being released
 * @return      0
 */
int trace_fput(struct pt_regs *ctx, struct file *file) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file(file)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.tid = tid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_CLOSE;
  data.inode = get_file_inode(file);
  data.size = 0;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace mmap file mappings
 *
 * Captures memory-mapped file regions. mmap protection and mapping flags
 * are stored in dedicated fields (mmap_prot and mmap_flags).
 *
 * @param ctx   BPF context
 * @param file  File being mapped (NULL for anonymous mappings)
 * @param addr  Requested mapping address
 * @param len   Mapping length in bytes
 * @param prot  Protection flags (PROT_READ, PROT_WRITE, etc.)
 * @param flags Mapping flags (MAP_SHARED, MAP_PRIVATE, etc.)
 * @return      0
 */
int trace_mmap_entry(struct pt_regs *ctx, struct file *file, unsigned long addr,
                     unsigned long len, unsigned long prot,
                     unsigned long flags) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!file || !is_regular_file(file)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.tid = tid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_MMAP;
  data.inode = get_file_inode(file);
  data.size = len;
  get_file_path(file, data.filename, sizeof(data.filename));
  data.mmap_prot = (u32)prot;
  data.mmap_flags = (u32)flags;
  mmap_staging.update(&pid_tgid, &data);

  return 0;
}

int trace_mmap_ret(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct data_t *staged = mmap_staging.lookup(&pid_tgid);
  if (!staged) {
    return 0;
  }

  long ret = PT_REGS_RC(ctx);
  if (ret < 0) {
    mmap_staging.delete(&pid_tgid);
    return 0;
  }

  staged->address = (u64)ret;
  events.perf_submit(ctx, staged, sizeof(*staged));
  mmap_staging.delete(&pid_tgid);
  return 0;
}

/**
 * @brief Trace munmap() - Memory unmapping
 *
 * Captures memory region unmappings. Does not have file context.
 *
 * @param ctx  BPF context
 * @param addr Start address being unmapped
 * @param len  Length being unmapped
 * @return     0
 */
int trace_munmap(struct pt_regs *ctx, unsigned long addr, size_t len) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.tid = tid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_MUNMAP;
  data.inode = 0;
  data.size = len;
  data.address = addr;
  data.flags = 0;

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/* ============================================================================
 * MREMAP PROBES
 * ============================================================================
 * mremap() can move a mapping to a new address and/or resize it. We need
 * both the old address (entry probe) and the new address (return value) to
 * correctly update the userspace mmap_regions cache.
 */

/**
 * @brief kprobe entry for sys_mremap - save arguments in staging map
 *
 * @param ctx  BPF context
 * @return     0
 */
int trace_mremap_entry(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct mremap_args args = {};
  args.old_addr = (u64)PT_REGS_PARM1(ctx);
  args.old_len  = (u64)PT_REGS_PARM2(ctx);
  args.new_len  = (u64)PT_REGS_PARM3(ctx);
  args.flags    = (u64)PT_REGS_PARM4(ctx);

  mremap_staging.update(&pid_tgid, &args);
  return 0;
}

#if defined(__x86_64__)
/**
 * @brief kprobe entry for the __x64_sys_mremap syscall wrapper.
 *
 * With CONFIG_ARCH_HAS_SYSCALL_WRAPPER (x86-64 since 4.17), __x64_sys_*
 * functions receive a single struct pt_regs * holding the user registers;
 * the syscall arguments are NOT in the probe's own PARM1-4 (reading them
 * there yields the pt_regs pointer and junk). This variant unwraps the
 * inner registers (di, si, dx, r10 per the syscall ABI).
 *
 * @param ctx  BPF context (PARM1 = user pt_regs)
 * @return     0
 */
int trace_mremap_entry_x64(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct pt_regs *uregs = (struct pt_regs *)PT_REGS_PARM1(ctx);
  if (!uregs) {
    return 0;
  }

  struct mremap_args args = {};
  bpf_probe_read_kernel(&args.old_addr, sizeof(args.old_addr), &uregs->di);
  bpf_probe_read_kernel(&args.old_len, sizeof(args.old_len), &uregs->si);
  bpf_probe_read_kernel(&args.new_len, sizeof(args.new_len), &uregs->dx);
  bpf_probe_read_kernel(&args.flags, sizeof(args.flags), &uregs->r10);

  mremap_staging.update(&pid_tgid, &args);
  return 0;
}
#endif /* __x86_64__ */

/**
 * @brief kretprobe return for sys_mremap - emit event with old + new addresses
 *
 * On success the kernel returns the new mapping address. On failure it returns
 * a negative errno value. Failed calls are discarded.
 *
 * @param ctx  BPF context (return value accessible via PT_REGS_RC)
 * @return     0
 */
int trace_mremap_ret(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct mremap_args *staged = mremap_staging.lookup(&pid_tgid);
  if (!staged) {
    return 0;
  }

  long ret = PT_REGS_RC(ctx);
  if (ret < 0) {
    mremap_staging.delete(&pid_tgid);
    return 0;
  }

  u32 pid = pid_tgid >> 32;

  struct data_t data = {};
  data.pid      = pid;
  data.ts       = bpf_ktime_get_ns();
  data.op       = OP_MREMAP;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.old_addr = staged->old_addr;
  data.old_size = staged->old_len;
  data.address  = (u64)ret;          /* new_addr returned by the kernel */
  data.size     = staged->new_len;
  data.flags    = (u32)staged->flags;

  events.perf_submit(ctx, &data, sizeof(data));
  mremap_staging.delete(&pid_tgid);
  return 0;
}

/* ============================================================================
 * PROCESS LIFECYCLE TRACEPOINTS
 * ============================================================================
 * execve() replaces the entire address space, so any mmap_regions tracked
 * for that PID are stale. On exit, all mappings are released. These
 * tracepoints let userspace clean up the region cache immediately.
 */

/**
 * @brief sched_process_exec tracepoint - new executable loaded
 *
 * execve() destroys the entire virtual address space of the calling process.
 * Signal userspace to clear all mmap_regions entries for this PID.
 */
TRACEPOINT_PROBE(sched, sched_process_exec) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts  = bpf_ktime_get_ns();
  data.op  = OP_PROCESS_EXEC;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  events.perf_submit(args, &data, sizeof(data));
  return 0;
}

/**
 * @brief sched_process_exit tracepoint - process is terminating
 *
 * All virtual memory regions are freed. Signal userspace to clear all
 * mmap_regions entries for this PID.
 */
TRACEPOINT_PROBE(sched, sched_process_exit) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts  = bpf_ktime_get_ns();
  data.op  = OP_PROCESS_EXIT;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  events.perf_submit(args, &data, sizeof(data));
  return 0;
}

/**
 * @brief Trace vfs_getattr() - File attribute queries (stat)
 *
 * Captures stat(), lstat(), fstat() calls for file metadata access.
 *
 * @param ctx          BPF context
 * @param path         Path being queried
 * @param stat         Output stat buffer
 * @param request_mask Requested attributes mask
 * @param query_flags  Query flags
 * @return             0
 */
int trace_vfs_getattr(struct pt_regs *ctx, const struct path *path,
                      struct kstat *stat, u32 request_mask,
                      unsigned int query_flags) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_GETATTR;
  data.size = 0;
  data.flags = 0;

  struct dentry *path_dentry = NULL;
  bpf_probe_read_kernel(&path_dentry, sizeof(path_dentry), &path->dentry);
  if (path_dentry) {
    const unsigned char *name_ptr = NULL;
    bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &path_dentry->d_name.name);
    if (name_ptr) {
      bpf_probe_read_kernel_str(data.filename, sizeof(data.filename), name_ptr);
    }
    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &path_dentry->d_inode);
    if (d_inode) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &d_inode->i_ino);
    }
  }

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace notify_change() - File attribute modifications
 *
 * Captures chmod(), chown(), utimes() and similar operations.
 * Attached to notify_change() which has the signature:
 *   int notify_change(struct mnt_idmap *, struct dentry *, struct iattr *, struct inode **)
 * so dentry is the SECOND argument (PT_REGS_PARM2).
 *
 * @param ctx  BPF context
 * @return     0
 */
int trace_vfs_setattr(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  /* notify_change: arg1 = mnt_idmap*, arg2 = dentry*, arg3 = iattr* */
  struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
  if (!dentry) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_SETATTR;
  data.size = 0;
  data.flags = 0;

  const unsigned char *name_ptr = NULL;
  bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);
  if (name_ptr) {
    bpf_probe_read_kernel_str(data.filename, sizeof(data.filename), name_ptr);
  }
  struct inode *d_inode = NULL;
  bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
  if (d_inode) {
    bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &d_inode->i_ino);
  }

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace chdir syscall - Working directory changes
 *
 * Tracepoint probe for chdir() syscall entry.
 * Filename field contains the target directory path.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_chdir) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_CHDIR;
  data.inode = 0;
  data.size = 0;

  bpf_probe_read_user_str(data.filename, sizeof(data.filename),
                          (void *)args->filename);
  data.flags = 0;

  events.perf_submit(args, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace iterate_dir() - Directory reading
 *
 * Captures getdents/readdir operations on directories.
 *
 * @param ctx      BPF context
 * @param file     Directory file being read
 * @param ctx_dir  Directory iteration context
 * @return         0
 */
int trace_readdir(struct pt_regs *ctx, struct file *file,
                  struct dir_context *ctx_dir) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_READDIR;
  data.inode = get_file_inode(file);
  data.size = 0;
  get_file_path(file, data.filename, sizeof(data.filename));
  bpf_probe_read_kernel(&data.flags, sizeof(data.flags), &file->f_flags);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/**
 * @brief Trace vfs_unlink() - File deletion
 *
 * Captures file unlink operations (removing directory entries).
 *
 * @param ctx     BPF context
 * @param dir     Parent directory inode
 * @param dentry  Dentry being unlinked
 * @return        0
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
int trace_vfs_unlink(struct pt_regs *ctx, void *idmap, struct inode *dir,
                     struct dentry *dentry) {
#else
int trace_vfs_unlink(struct pt_regs *ctx, struct inode *dir,
                     struct dentry *dentry) {
#endif
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tid = (u32)pid_tgid;
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.tid = tid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_UNLINK;
  data.size = 0;
  data.flags = 0;

  if (dentry) {
    const unsigned char *name_ptr = NULL;
    bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);
    if (name_ptr) {
      bpf_probe_read_kernel_str(data.filename, sizeof(data.filename), name_ptr);
    }
    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (d_inode) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &d_inode->i_ino);
    }
  }

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Trace vfs_truncate() - File size truncation
 *
 * Captures truncate()/ftruncate() operations that change file size.
 *
 * @param ctx   BPF context
 * @param path  Path being truncated
 * @return      0
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
int trace_vfs_truncate(struct pt_regs *ctx, void *idmap, struct dentry *dentry) {
#else
int trace_vfs_truncate(struct pt_regs *ctx, struct dentry *dentry) {
#endif
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_TRUNCATE;
  data.size = 0;
  data.flags = 0;

  if (dentry) {
    const unsigned char *name_ptr = NULL;
    bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);
    if (name_ptr) {
      bpf_probe_read_kernel_str(data.filename, sizeof(data.filename), name_ptr);
    }
    struct inode *d_inode = NULL;
    bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
    if (d_inode) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &d_inode->i_ino);
    }
  }

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Trace ksys_sync() - System-wide sync
 *
 * Captures sync() syscall that flushes all filesystem buffers.
 *
 * @param ctx  BPF context
 * @return     0
 */
int trace_ksys_sync(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_SYNC;
  data.inode = 0;
  data.size = 0;
  data.flags = 0;

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

/* NOTE: fdatasync() is captured by trace_vfs_fsync/trace_vfs_fsync_range via
 * the datasync argument (OP_FDATASYNC); a dedicated sys_enter_fdatasync
 * tracepoint would double-count it. */

/* ============================================================================
 * DUAL-PATH FILESYSTEM OPERATION PROBES
 * ============================================================================
 * Operations involving two paths (source and destination) use the larger
 * data_dual_t structure allocated from per-CPU array.
 */

/**
 * @brief Trace vfs_rename() - File/directory rename
 *
 * Captures rename()/renameat() operations with source and destination paths.
 * Uses per-CPU buffer for the 572-byte data_dual_t structure.
 * Kernel 6.x signature: vfs_rename(struct renamedata *rd)
 *
 * @param ctx  BPF context
 * @param rd   Rename data structure containing old/new dentry info
 * @return     0
 */
int trace_vfs_rename(struct pt_regs *ctx, struct renamedata_bpf *rd) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!rd) {
    return 0;
  }

  // Read dentry pointers from renamedata struct
  struct dentry *old_dentry = NULL;
  struct dentry *new_dentry = NULL;
  bpf_probe_read_kernel(&old_dentry, sizeof(old_dentry), &rd->old_dentry);
  bpf_probe_read_kernel(&new_dentry, sizeof(new_dentry), &rd->new_dentry);

  if (!old_dentry || !new_dentry) {
    return 0;
  }

  // Use per-CPU array to avoid stack limit (data_dual_t is 572 bytes, stack limit is 512)
  u32 zero = 0;
  struct data_dual_t *data = dual_data_buffer.lookup(&zero);
  if (!data) {
    return 0;
  }
  
  // Zero-initialize filename buffers to avoid stale data
  __builtin_memset(data->filename_old, 0, FILENAME_MAX_LEN);
  __builtin_memset(data->filename_new, 0, FILENAME_MAX_LEN);
  
  data->pid = pid;
  data->ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data->comm, sizeof(data->comm));
  data->op = OP_RENAME;

  // Get old path and inode
  data->inode_old = get_file_inode_from_dentry(old_dentry);
  get_file_path_from_dentry(old_dentry, data->filename_old, sizeof(data->filename_old));

  // Get new path and inode
  data->inode_new = get_file_inode_from_dentry(new_dentry);
  get_file_path_from_dentry(new_dentry, data->filename_new, sizeof(data->filename_new));

  data->flags = 0;
  data->latency_ns = 0;

  events_dual.perf_submit(ctx, data, sizeof(*data));
  return 0;
}

/**
 * @brief Trace vfs_mkdir() - Directory creation
 *
 * Captures mkdir() operations. Mode field contains permission bits.
 *
 * @param ctx     BPF context
 * @param dir     Parent directory inode
 * @param dentry  New directory dentry
 * @param mode    Permission mode (e.g., 0755)
 * @return        0
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
int trace_vfs_mkdir(struct pt_regs *ctx, void *idmap, struct inode *dir,
                    struct dentry *dentry, umode_t mode) {
#else
int trace_vfs_mkdir(struct pt_regs *ctx, struct inode *dir,
                    struct dentry *dentry, umode_t mode) {
#endif
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!dentry) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_MKDIR;
  data.size = 0;
  data.flags = mode;

  const unsigned char *name_ptr = NULL;
  bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);
  if (name_ptr) {
    bpf_probe_read_kernel_str(data.filename, sizeof(data.filename), name_ptr);
  }
  struct inode *d_inode = NULL;
  bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
  if (d_inode) {
    bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &d_inode->i_ino);
  }

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Trace vfs_rmdir() - Directory removal
 *
 * Captures rmdir() operations.
 *
 * @param ctx     BPF context
 * @param dir     Parent directory inode
 * @param dentry  Directory being removed
 * @return        0
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
int trace_vfs_rmdir(struct pt_regs *ctx, void *idmap, struct inode *dir,
                    struct dentry *dentry) {
#else
int trace_vfs_rmdir(struct pt_regs *ctx, struct inode *dir,
                    struct dentry *dentry) {
#endif
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!dentry) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_RMDIR;
  data.size = 0;
  data.flags = 0;

  const unsigned char *name_ptr = NULL;
  bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);
  if (name_ptr) {
    bpf_probe_read_kernel_str(data.filename, sizeof(data.filename), name_ptr);
  }
  struct inode *d_inode = NULL;
  bpf_probe_read_kernel(&d_inode, sizeof(d_inode), &dentry->d_inode);
  if (d_inode) {
    bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &d_inode->i_ino);
  }

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Trace vfs_link() - Hard link creation
 *
 * Captures link() operations. Both dentries will share the same inode.
 * Kernel 6.x signature: vfs_link(old_dentry, mnt_idmap, dir, new_dentry, ...)
 *
 * @param ctx         BPF context
 * @param old_dentry  Existing file dentry
 * @param idmap       Mount ID map (kernel 6.x)
 * @param dir         Directory where link is created
 * @param new_dentry  New link dentry
 * @return            0
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
int trace_vfs_link(struct pt_regs *ctx, struct dentry *old_dentry,
                   void *idmap, struct inode *dir, struct dentry *new_dentry) {
#else
int trace_vfs_link(struct pt_regs *ctx, struct dentry *old_dentry,
                   struct inode *dir, struct dentry *new_dentry) {
#endif
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!old_dentry || !new_dentry) {
    return 0;
  }

  // Use per-CPU array to avoid stack limit
  u32 zero = 0;
  struct data_dual_t *data = dual_data_buffer.lookup(&zero);
  if (!data) {
    return 0;
  }
  
  // Zero-initialize filename buffers to avoid stale data
  __builtin_memset(data->filename_old, 0, FILENAME_MAX_LEN);
  __builtin_memset(data->filename_new, 0, FILENAME_MAX_LEN);
  
  data->pid = pid;
  data->ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data->comm, sizeof(data->comm));
  data->op = OP_LINK;

  // Get old path and inode
  data->inode_old = get_file_inode_from_dentry(old_dentry);
  get_file_path_from_dentry(old_dentry, data->filename_old, sizeof(data->filename_old));

  // Get new path and inode
  data->inode_new = get_file_inode_from_dentry(new_dentry);
  get_file_path_from_dentry(new_dentry, data->filename_new, sizeof(data->filename_new));

  data->flags = 0;
  data->latency_ns = 0;

  events_dual.perf_submit(ctx, data, sizeof(*data));
  return 0;
}

/**
 * @brief Trace vfs_symlink() - Symbolic link creation
 *
 * Captures symlink() operations. filename_old contains target path,
 * filename_new contains the symlink name.
 * Kernel 6.x signature: vfs_symlink(mnt_idmap, dir, dentry, oldname)
 *
 * @param ctx     BPF context
 * @param idmap   Mount ID map (kernel 6.x)
 * @param dir     Directory where symlink is created
 * @param dentry  New symlink dentry
 * @param oldname Target path (symlink content)
 * @return        0
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
int trace_vfs_symlink(struct pt_regs *ctx, void *idmap, struct inode *dir,
                      struct dentry *dentry, const char *oldname) {
#else
int trace_vfs_symlink(struct pt_regs *ctx, struct inode *dir,
                      struct dentry *dentry, const char *oldname) {
#endif
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!dentry) {
    return 0;
  }

  // Use per-CPU array to avoid stack limit
  u32 zero = 0;
  struct data_dual_t *data = dual_data_buffer.lookup(&zero);
  if (!data) {
    return 0;
  }
  
  // Zero-initialize filename buffers to avoid stale data
  __builtin_memset(data->filename_old, 0, FILENAME_MAX_LEN);
  __builtin_memset(data->filename_new, 0, FILENAME_MAX_LEN);
  
  data->pid = pid;
  data->ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data->comm, sizeof(data->comm));
  data->op = OP_SYMLINK;
  
  // filename_old is the target of the symlink (try user pointer first, then kernel)
  if (oldname) {
    int ret = bpf_probe_read_user_str(data->filename_old, sizeof(data->filename_old), oldname);
    if (ret <= 0) {
      bpf_probe_read_kernel_str(data->filename_old, sizeof(data->filename_old), oldname);
    }
  }
  
  // filename_new is the link name
  get_file_path_from_dentry(dentry, data->filename_new, sizeof(data->filename_new));
  
  data->inode_old = 0;
  data->inode_new = get_file_inode_from_dentry(dentry);
  data->flags = 0;
  data->latency_ns = 0;

  events_dual.perf_submit(ctx, data, sizeof(*data));
  return 0;
}

/**
 * @brief Trace vfs_fallocate() - File space pre-allocation
 *
 * Captures fallocate() calls for pre-allocating disk space.
 * Mode field contains FALLOC_FL_* flags.
 *
 * @param ctx    BPF context
 * @param file   File to allocate space for
 * @param mode   Allocation mode flags
 * @param offset Starting offset
 * @param len    Length to allocate
 * @return       0
 */
int trace_vfs_fallocate(struct pt_regs *ctx, struct file *file, int mode,
                        loff_t offset, loff_t len) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!is_regular_file(file)) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_FALLOCATE;
  data.inode = get_file_inode(file);
  data.size = len;
  get_file_path(file, data.filename, sizeof(data.filename));
  data.flags = mode;

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Trace sendfile() - Zero-copy file-to-socket transfer
 *
 * Captures sendfile() operations for efficient file serving.
 * Does not have direct access to file structures, only FDs.
 *
 * @param ctx    BPF context
 * @param out_fd Destination (socket) file descriptor
 * @param in_fd  Source (file) file descriptor
 * @param offset File offset for reading
 * @param count  Bytes to transfer
 * @return       0
 */
int trace_sendfile(struct pt_regs *ctx, int out_fd, int in_fd, loff_t *offset,
                   size_t count) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct data_t data = {};
  data.pid = pid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_SENDFILE;
  data.inode = 0;
  data.size = count;
  data.flags = 0;

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* ============================================================================
 * BLOCK LAYER TRACEPOINTS
 * ============================================================================
 * Block layer tracing captures disk I/O at the request queue level.
 * Three events track request lifecycle: insert -> issue -> complete
 */

/**
 * @brief Build the correlation key for a block request.
 *
 * MUST be used by insert, issue, and complete alike: any divergence (the
 * complete probe previously masked the sector to 32 bits while insert/issue
 * XOR'd the full value) makes lookups fail for sectors >= 2^32 — i.e. all
 * I/O beyond the 2 TiB boundary of a device silently disappears from the
 * trace. CPU ID is intentionally not part of the key because completion may
 * run on a different CPU than submission.
 */
static __always_inline struct block_rq_key_t block_rq_key(u32 dev, u64 sector) {
  struct block_rq_key_t key = {};
  key.dev = dev;
  key.sector = sector;
  return key;
}

/**
 * @brief Block request insert tracepoint
 *
 * Records when a request enters the I/O scheduler queue.
 * Used to calculate queue time (insert to issue latency).
 */
TRACEPOINT_PROBE(block, block_rq_insert) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 key_pid = 0;
  u32 *tracer_pid = tracer_config.lookup(&key_pid);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  // Store insert timestamp for queue time calculation
  struct block_rq_key_t key = block_rq_key(args->dev, args->sector);
  u64 ts = bpf_ktime_get_ns();
  block_insert_times.update(&key, &ts);

  return 0;
}

/**
 * @brief Block request issue tracepoint
 *
 * Records when a request is submitted to the device driver, together with
 * the submitting task's identity. The completion handler runs in IRQ/softirq
 * context where "current" is unrelated to the I/O, so pid/comm/ppid must be
 * captured here and carried to the completion event.
 */
TRACEPOINT_PROBE(block, block_rq_issue) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 key_pid = 0;
  u32 *tracer_pid = tracer_config.lookup(&key_pid);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct block_rq_key_t key = block_rq_key(args->dev, args->sector);
  struct block_issue_ctx ictx = {};
  ictx.ts = bpf_ktime_get_ns();
  ictx.pid = pid;
  ictx.tid = (u32)pid_tgid;
  ictx.ppid = get_ppid();
  bpf_get_current_comm(&ictx.comm, sizeof(ictx.comm));
  block_start_times.update(&key, &ictx);

  return 0;
}

/**
 * @brief Block request completion tracepoint
 *
 * Records when I/O completes, calculates latencies, and emits event.
 * Computes both device latency (issue->complete) and queue latency.
 */
TRACEPOINT_PROBE(block, block_rq_complete) {
  // Must use the same key formula as block_rq_issue/insert.
  struct block_rq_key_t key = block_rq_key(args->dev, args->sector);
  struct block_issue_ctx *ictx = block_start_times.lookup(&key);
  if (!ictx)
    return 0;

  // Filter the tracer's own I/O by the SUBMITTER pid — the current pid here
  // is the interrupted task, not the process that did the I/O.
  u32 key_pid = 0;
  u32 *tracer_pid = tracer_config.lookup(&key_pid);
  if (tracer_pid && ictx->pid == *tracer_pid) {
    block_start_times.delete(&key);
    block_insert_times.delete(&key);
    return 0;
  }

  u64 end_ts = bpf_ktime_get_ns();
  u64 latency = end_ts - ictx->ts;

  // Calculate queue time (time from insert to issue)
  u64 queue_time = 0;
  u64 *insert_ts = block_insert_times.lookup(&key);
  if (insert_ts && ictx->ts >= *insert_ts) {
    queue_time = ictx->ts - *insert_ts;
  }

  struct block_event event = {};
  event.ts = end_ts;
  // Attribution from issue time: the submitting task, not the completion
  // context (which is frequently swapper/N in softirq).
  event.pid = ictx->pid;
  event.tid = ictx->tid;
  event.ppid = ictx->ppid;
  __builtin_memcpy(event.comm, ictx->comm, sizeof(event.comm));
  event.cpu_id = bpf_get_smp_processor_id();

  event.sector = args->sector;
  
  // Calculate bio_size (nr_sector is u32, so shifting by 9 never overflows u64)
  event.bio_size = ((u64)args->nr_sector) << 9;
  
  event.latency_ns = latency;
  event.queue_time_ns = queue_time;  // New: queue time
  
#ifdef HAS_CMD_FLAGS
  event.cmd_flags = args->cmd_flags; // Capture REQ_* command flags
  // Extract raw operation code from cmd_flags (lower 8 bits contain REQ_OP_*)
  event.op_code = args->cmd_flags & 0xFF;
#else
  event.cmd_flags = 0; // Field not available in newer kernels
  event.op_code = 0;   // Cannot extract op_code without cmd_flags
#endif
  
  // Capture device number for partition identification
  // dev contains major:minor encoding (major in bits 8-15, minor in bits 0-7 on older kernels,
  // or major in bits 8-15, minor in bits 0-15 with extensions on newer kernels)
  event.dev = args->dev;

  bpf_probe_read_kernel(&event.op, sizeof(event.op), &args->rwbs);

  bl_events.perf_submit(args, &event, sizeof(event));

  block_start_times.delete(&key);
  block_insert_times.delete(&key);
  return 0;
}

/* ============================================================================
 * PAGE CACHE PROBES
 * ============================================================================
 * Page cache probes track memory-cached file pages. Kernel 5.16+ uses
 * "folio" (multi-page unit), older kernels use "page" structures.
 */

/**
 * @brief Cache hit probe - folio version (kernel >= 5.16)
 *
 * folio_mark_accessed() is called when a cached page is accessed.
 * Indicates data was served from cache without disk I/O.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
int trace_folio_mark_accessed(struct pt_regs *ctx, struct folio *folio) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_HIT;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (folio) {
    // Read index first so populate_cache_metadata can calculate offset
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);
    
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &folio->mapping);
    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Cache hit probe - page version (kernel < 5.17)
 *
 * mark_page_accessed() for older kernels without folio API.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_hit(struct pt_regs *ctx, struct page *page) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_HIT;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (page) {
    // Read index first so populate_cache_metadata can calculate offset
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &page->index);
    
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &page->mapping);
    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Cache miss probe - folio version (kernel >= 5.16)
 *
 * filemap_add_folio() adds a new page to cache after disk read.
 * This indicates a cache miss that required actual disk I/O.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
int trace_filemap_add_folio(struct pt_regs *ctx, struct address_space *mapping,
                            struct folio *folio, pgoff_t index, gfp_t gfp) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_MISS;
  data.index = index;  // Set before calling populate_cache_metadata
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Cache miss probe - page version (kernel < 5.17)
 *
 * add_to_page_cache_lru() for older kernels.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_miss(struct pt_regs *ctx, struct page *page,
               struct address_space *mapping, pgoff_t offset, gfp_t gfp_mask) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_MISS;
  data.index = offset;  // Set before calling populate_cache_metadata
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Dirty page probe - page version (kernel < 5.17)
 *
 * account_page_dirtied() marks a page as modified.
 * Dirty pages need writeback before eviction.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_account_page_dirtied(struct pt_regs *ctx, struct page *page,
                               struct address_space *mapping) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_DIRTY;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (page) {
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &page->index);
  }

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Dirty page probe - folio version (kernel >= 5.17)
 *
 * folio_mark_dirty() marks a folio as modified in newer kernels.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
int trace_folio_mark_dirty(struct pt_regs *ctx, struct folio *folio) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_DIRTY;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (folio) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &folio->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Writeback start probe - page version (kernel < 5.17)
 *
 * clear_page_dirty_for_io() initiates writeback of dirty page.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_clear_page_dirty_for_io(struct pt_regs *ctx, struct page *page) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_WRITEBACK_START;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (page) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &page->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &page->index);

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Writeback start probe - folio version (kernel >= 5.17)
 *
 * folio_clear_dirty_for_io() starts writeback in newer kernels.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
int trace_folio_clear_dirty_for_io(struct pt_regs *ctx, struct folio *folio) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_WRITEBACK_START;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (folio) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &folio->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Writeback completion probe - page version (kernel < 5.17)
 *
 * test_clear_page_writeback() completes writeback of a page.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_test_clear_page_writeback(struct pt_regs *ctx, struct page *page) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_WRITEBACK_END;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (page) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &page->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &page->index);

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Writeback completion probe - folio version (kernel >= 5.17)
 *
 * folio_end_writeback() signals writeback completion.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
int trace_folio_end_writeback(struct pt_regs *ctx, struct folio *folio) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_WRITEBACK_END;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (folio) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &folio->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Cache eviction probe - folio version (kernel >= 5.17)
 *
 * filemap_remove_folio() evicts pages from cache under memory pressure.
 * Process name "kswapd*" indicates background reclaim, others direct reclaim.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
int trace_filemap_remove_folio(struct pt_regs *ctx, struct folio *folio) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_EVICT;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  
  // Detect reclaim context from process name
  // kswapd process indicates background reclaim
  if (data.comm[0] == 'k' && data.comm[1] == 's' && data.comm[2] == 'w' && 
      data.comm[3] == 'a' && data.comm[4] == 'p' && data.comm[5] == 'd') {
  } else if (pid > 0) {
    // Non-kswapd process doing eviction likely in direct reclaim
  } else {
  }

  if (folio) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &folio->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);

    // Get LRU type from folio/page flags
    // In folio, flags are in the first page (folio is a page array)
    // Try reading flags from folio as if it were a page struct
    unsigned long flags = 0;
    // Cast folio pointer to page pointer to read flags
    struct page *p = (struct page *)folio;
    bpf_probe_read_kernel(&flags, sizeof(flags), &p->flags);
    if (flags != 0) {
    }

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Cache eviction probe - page version (kernel < 5.17)
 *
 * delete_from_page_cache() for older kernels.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_delete_from_page_cache(struct pt_regs *ctx, struct page *page) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_EVICT;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  
  // Detect reclaim context from process name
  if (data.comm[0] == 'k' && data.comm[1] == 's' && data.comm[2] == 'w' && 
      data.comm[3] == 'a' && data.comm[4] == 'p' && data.comm[5] == 'd') {
  } else if (pid > 0) {
  } else {
  }

  if (page) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &page->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &page->index);

    // Get LRU type from page flags
    unsigned long flags = 0;
    bpf_probe_read_kernel(&flags, sizeof(flags), &page->flags);
    if (flags != 0) {
    }

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Cache eviction tracepoint - most reliable method
 *
 * Tracepoint probe that works across kernel versions.
 * Particularly reliable for catching drop_caches operations.
 */
TRACEPOINT_PROBE(filemap, mm_filemap_delete_from_page_cache) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_EVICT;
  data.inode = args->i_ino;
  data.index = args->index;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.count = 1;  // Single page from tracepoint
  data.size = 0;  // No inode struct access in tracepoint
  data.dev_id = 0;  // No device ID available in tracepoint

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(args, &data, sizeof(data));
  return 0;
}

/**
 * @brief Cache invalidation probe - invalidate_mapping_pages()
 *
 * Captures explicit page invalidation (not eviction).
 * Count field contains number of pages in the invalidated range.
 */
int trace_invalidate_mapping(struct pt_regs *ctx, struct address_space *mapping,
                             pgoff_t start, pgoff_t end) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_INVALIDATE;
  data.index = start;  // Set before calling populate_cache_metadata
  data.count = (end >= start) ? (u32)(end - start + 1) : 0;  // Inclusive page range
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Cache invalidation probe - truncate_inode_pages_range()
 *
 * Captures page invalidation during file truncation.
 * Byte offsets are converted to page ranges.
 */
int trace_truncate_pages(struct pt_regs *ctx, struct address_space *mapping,
                         loff_t lstart, loff_t lend) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_INVALIDATE;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  /* Compute page range using PAGE_SHIFT to avoid hardcoded page size and
   * off-by-one issues if lend is inclusive.
   */
  pgoff_t start_index = (pgoff_t)(lstart >> PAGE_SHIFT);
  pgoff_t end_index = (pgoff_t)(lend >> PAGE_SHIFT);

  data.index = start_index;  // starting page index
  if (end_index >= start_index)
    data.count = (u32)(end_index - start_index + 1);
  else
    data.count = 0;

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/**
 * @brief Cache drop probe - folio version (kernel >= 5.18)
 *
 * Captures explicit cache drops (e.g., POSIX_FADV_DONTNEED).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
int trace_cache_drop_folio(struct pt_regs *ctx, struct address_space *mapping,
                           struct folio *folio) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_DROP;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (folio) {
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &folio->index);
    
    // Get LRU type from folio/page flags
    unsigned long flags = 0;
    struct page *p = (struct page *)folio;
    bpf_probe_read_kernel(&flags, sizeof(flags), &p->flags);
    if (flags != 0) {
    }
  }

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Cache drop probe - page version (kernel < 5.17)
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
int trace_cache_drop_page(struct pt_regs *ctx, struct page *page) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_DROP;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (page) {
    struct address_space *mapping = NULL;
    bpf_probe_read_kernel(&mapping, sizeof(mapping), &page->mapping);
    bpf_probe_read_kernel(&data.index, sizeof(data.index), &page->index);

    // Get LRU type from page flags
    unsigned long flags = 0;
    bpf_probe_read_kernel(&flags, sizeof(flags), &page->flags);
    if (flags != 0) {
    }

    if (mapping) {
      struct inode *host = NULL;
      bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
      if (host) {
        bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
        populate_cache_metadata(&data, host);
      }
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Cache readahead probe - prefetch tracking
 *
 * Captures kernel readahead (prefetch) operations that speculatively
 * load pages into cache. count field contains pages being prefetched.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
int trace_do_page_cache_readahead(struct pt_regs *ctx, struct address_space *mapping,
                                   struct file *file, pgoff_t index, unsigned long nr_pages) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_READAHEAD;
  data.index = index;  // Set before calling populate_cache_metadata
  data.count = (u32)nr_pages;  // Number of pages in readahead window
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  if (mapping) {
    struct inode *host = NULL;
    bpf_probe_read_kernel(&host, sizeof(host), &mapping->host);
    if (host) {
      bpf_probe_read_kernel(&data.inode, sizeof(data.inode), &host->i_ino);
      populate_cache_metadata(&data, host);
    }
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/**
 * @brief Cache reclaim probe - memory pressure tracking
 *
 * shrink_folio_list() is called during memory reclaim.
 * kswapd = background reclaim, other processes = direct reclaim.
 * Direct reclaim indicates memory pressure affecting performance.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
int trace_shrink_folio_list(struct pt_regs *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  // Note: shrink_folio_list operates on a list, so we emit a generic reclaim event
  // Individual folio details would require iterating the list, which is complex in eBPF
  struct cache_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.type = CACHE_RECLAIM;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.inode = 0;  // No specific inode for list-based reclaim
  data.index = 0;
  data.count = 0;  // Would need list iteration to count
  
  // Detect reclaim source: kswapd vs direct reclaim
  // kswapd comm starts with "kswapd"
  if (data.comm[0] == 'k' && data.comm[1] == 's' && data.comm[2] == 'w' && data.comm[3] == 'a' && data.comm[4] == 'p' && data.comm[5] == 'd') {
  } else {
  }

  data.cpu_id = bpf_get_smp_processor_id();
  cache_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
#endif

/* ============================================================================
 * PAGE FAULT TRACING
 * ============================================================================
 * Page faults occur when accessing memory-mapped files. Major faults
 * require disk I/O, minor faults are served from page cache.
 */

/**
 * @brief File-backed page fault probe
 *
 * filemap_fault() handles page faults for memory-mapped files.
 * Captures the faulting address, file offset, and fault type.
 * Major/minor fault distinction requires return probe analysis.
 *
 * @param ctx  BPF context
 * @param vmf  VM fault context containing fault details
 * @return     0
 */
int trace_filemap_fault_entry(struct pt_regs *ctx, struct vm_fault *vmf) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct pagefault_data data = {};
  data.ts = bpf_ktime_get_ns();
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  
  if (vmf) {
    // Get faulting address
    bpf_probe_read_kernel(&data.address, sizeof(data.address), &vmf->address);
    
    // Get page offset (file offset in pages)
    bpf_probe_read_kernel(&data.offset, sizeof(data.offset), &vmf->pgoff);
    
    // Determine if this is a write fault
    unsigned int flags = 0;
    bpf_probe_read_kernel(&flags, sizeof(flags), &vmf->flags);
    data.fault_type = (flags & 0x01) ? FAULT_WRITE : FAULT_READ;  // FAULT_FLAG_WRITE = 0x01
    
    // Get VMA to access the backing file
    struct vm_area_struct *vma = NULL;
    bpf_probe_read_kernel(&vma, sizeof(vma), &vmf->vma);
    if (vma) {
      struct file *file = NULL;
      bpf_probe_read_kernel(&file, sizeof(file), &vma->vm_file);
      if (file) {
        data.inode = get_file_inode(file);
        
        // Get device ID from superblock
        struct dentry *dentry = NULL;
        bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
        if (dentry) {
          struct super_block *sb = NULL;
          bpf_probe_read_kernel(&sb, sizeof(sb), &dentry->d_sb);
          if (sb) {
            bpf_probe_read_kernel(&data.dev_id, sizeof(data.dev_id), &sb->s_dev);
          }
        }
      }
    }
  }
  
  // Major/minor fault determination requires kretprobe
  data.major = 0;  // Will be updated by return probe if available

  pagefault_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* ============================================================================
 * DIRECT I/O TRACING
 * ============================================================================
 * Direct I/O bypasses the page cache for applications managing their
 * own caching (databases, etc.).
 */

/**
 * @brief Stage the direct I/O direction from the iov_iter for the kretprobe.
 *
 * The iov_iter encodes direction: data_source (>= 5.14) is true for writes;
 * older kernels keep the WRITE bit (bit 0) in iter->type. The return value
 * alone cannot distinguish read from write, so the direction must be read
 * here at entry and consumed by trace_dio_return.
 */
static __always_inline int stage_dio_direction(struct iov_iter *iter) {
  if (!iter) {
    return 0;
  }
  u8 is_write = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
  bool data_source = false;
  bpf_probe_read_kernel(&data_source, sizeof(data_source), &iter->data_source);
  is_write = data_source ? 1 : 0;
#else
  unsigned int type = 0;
  bpf_probe_read_kernel(&type, sizeof(type), &iter->type);
  is_write = (type & 1) ? 1 : 0;  /* WRITE == 1 */
#endif
  u64 pid_tgid = bpf_get_current_pid_tgid();
  dio_staging.update(&pid_tgid, &is_write);
  return 0;
}

/**
 * @brief Direct I/O entry probe for iomap_dio_rw (modern kernels).
 *
 * iomap_dio_rw(struct kiocb *iocb, struct iov_iter *iter, ...) — the
 * iov_iter is the second argument.
 */
int trace_dio_entry_iomap(struct pt_regs *ctx, struct kiocb *iocb,
                          struct iov_iter *iter) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;
  return stage_dio_direction(iter);
}

/**
 * @brief Direct I/O entry probe for __blockdev_direct_IO (legacy path).
 *
 * __blockdev_direct_IO(struct kiocb *iocb, struct inode *inode,
 *                      struct block_device *bdev, struct iov_iter *iter, ...)
 * — the iov_iter is the fourth argument.
 */
int trace_dio_entry_blockdev(struct pt_regs *ctx, struct kiocb *iocb,
                             struct inode *inode, struct block_device *bdev,
                             struct iov_iter *iter) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;
  return stage_dio_direction(iter);
}

/**
 * @brief Direct I/O return probe
 *
 * Emits a DIO completion event with the direction staged by the entry probe.
 * Return value is bytes transferred (positive) or error (negative).
 * If no direction was staged (probe attached mid-operation) the event is
 * skipped rather than guessing the direction.
 */
int trace_dio_return(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  u8 *is_write = dio_staging.lookup(&pid_tgid);
  if (!is_write)
    return 0;

  ssize_t ret = PT_REGS_RC(ctx);
  u64 end_ts = bpf_ktime_get_ns();

  // Emit as a special VFS event with DIO operation type
  struct data_t data = {};
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  data.ts = end_ts;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = (*is_write) ? OP_DIO_WRITE : OP_DIO_READ;
  data.size = (ret >= 0) ? (u64)ret : 0;
  data.ret_val = (s64)ret;

  events.perf_submit(ctx, &data, sizeof(data));
  dio_staging.delete(&pid_tgid);

  return 0;
}

/* ============================================================================
 * SPLICE TRACING
 * ============================================================================
 * splice() enables zero-copy data transfer between file descriptors
 * using kernel buffers (pipes) as intermediary.
 */

/**
 * @brief Zero-copy splice probe
 *
 * do_splice() transfers data between file descriptors without
 * copying through userspace. Commonly used for efficient file serving.
 *
 * @param ctx     BPF context
 * @param in      Input file (source)
 * @param off_in  Source offset
 * @param out     Output file (destination)
 * @param off_out Destination offset
 * @param len     Transfer length
 * @param flags   Splice flags (SPLICE_F_*)
 * @return        0
 */
int trace_splice(struct pt_regs *ctx, struct file *in, loff_t *off_in,
                 struct file *out, loff_t *off_out, size_t len, unsigned int flags) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct data_t data = {};
  data.pid = pid;
  data.tid = (u32)pid_tgid;
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_SPLICE;
  data.size = len;
  data.flags = flags;
  
  // Get source file info if available
  if (in) {
    data.inode = get_file_inode(in);
    get_file_path(in, data.filename, sizeof(data.filename));
    if (off_in) {
      bpf_probe_read_kernel(&data.offset, sizeof(data.offset), off_in);
    }
  }

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

/* ============================================================================
 * MEMORY-MAPPED I/O TRACING
 * ============================================================================
 * msync and madvise control how memory-mapped file regions
 * interact with storage and the page cache.
 */

/**
 * @brief msync() system call tracepoint
 *
 * Captures msync() calls that synchronize memory-mapped file
 * regions with storage. MS_SYNC, MS_ASYNC, MS_INVALIDATE flags.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_msync) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct data_t data = {};
  data.pid = pid;
  data.tid = bpf_get_current_pid_tgid();
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_MSYNC;
  data.offset = args->start;  // Store address as offset
  data.size = args->len;
  data.flags = args->flags;

  events.perf_submit(args, &data, sizeof(data));
  return 0;
}

/**
 * @brief madvise() system call tracepoint
 *
 * Captures madvise() calls that advise kernel about memory usage.
 * MADV_DONTNEED, MADV_WILLNEED, etc. affect page cache behavior.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_madvise) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid)
    return 0;

  struct data_t data = {};
  data.pid = pid;
  data.tid = bpf_get_current_pid_tgid();
  data.ts = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.op = OP_MADVISE;
  data.offset = args->start;  // Store address as offset
  data.size = args->len_in;
  data.flags = args->behavior;

  events.perf_submit(args, &data, sizeof(data));
  return 0;
}

/* ============================================================================
 * IO_URING TRACING PROBES
 * ============================================================================
 * Probes for tracing io_uring async I/O operations:
 * - io_uring_enter syscall (ENTER events)
 * - SQE submission (SUBMIT events)
 * - Request completion (COMPLETE events)
 * - Async worker execution (WORKER events)
 */

/**
 * @brief Trace io_uring_enter syscall
 *
 * Captures io_uring_enter() calls with submission and completion parameters.
 * This shows batch submission patterns and blocking behavior.
 *
 * @param ctx       BPF context
 * @param fd        io_uring file descriptor
 * @param to_submit Number of SQEs to submit
 * @param min_complete Minimum completions to wait for
 * @param flags     Enter flags (IORING_ENTER_*)
 * @return          0
 */
static __always_inline int emit_io_uring_enter(struct pt_regs *ctx, u32 fd,
                                               u32 to_submit, u32 min_complete,
                                               u32 flags) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  struct io_uring_event_data e = {};
  e.timestamp_ns = bpf_ktime_get_ns();
  e.event_type = IOURING_ENTER;
  e.pid = pid;
  e.tid = (u32)pid_tgid;
  bpf_get_current_comm(&e.comm, sizeof(e.comm));
  e.cpu = bpf_get_smp_processor_id();
  e.ring_fd = fd;
  e.to_submit = to_submit;
  e.min_complete = min_complete;
  e.enter_flags = flags;

  io_uring_events.perf_submit(ctx, &e, sizeof(e));
  return 0;
}

int trace_io_uring_enter(struct pt_regs *ctx, unsigned int fd,
                         unsigned int to_submit, unsigned int min_complete,
                         unsigned int flags) {
  return emit_io_uring_enter(ctx, fd, to_submit, min_complete, flags);
}

#if defined(__x86_64__)
/**
 * @brief Kprobe entry for the __x64_sys_io_uring_enter syscall wrapper.
 *
 * Unwraps the user pt_regs (see trace_mremap_entry_x64): fd/to_submit/
 * min_complete/flags live in di/si/dx/r10, not in the probe's PARM1-4.
 *
 * @param ctx  BPF context (PARM1 = user pt_regs)
 * @return     0
 */
int trace_io_uring_enter_x64(struct pt_regs *ctx) {
  struct pt_regs *uregs = (struct pt_regs *)PT_REGS_PARM1(ctx);
  if (!uregs) {
    return 0;
  }

  unsigned long fd = 0, to_submit = 0, min_complete = 0, flags = 0;
  bpf_probe_read_kernel(&fd, sizeof(fd), &uregs->di);
  bpf_probe_read_kernel(&to_submit, sizeof(to_submit), &uregs->si);
  bpf_probe_read_kernel(&min_complete, sizeof(min_complete), &uregs->dx);
  bpf_probe_read_kernel(&flags, sizeof(flags), &uregs->r10);

  return emit_io_uring_enter(ctx, (u32)fd, (u32)to_submit, (u32)min_complete,
                             (u32)flags);
}
#endif /* __x86_64__ */

/**
 * @brief ABI-stable subset of the io_uring SQE (uapi/linux/io_uring.h).
 *
 * struct io_uring_sqe is a UAPI structure whose leading field offsets are
 * stable across every kernel that supports io_uring. We mirror that prefix so
 * the prep probe can read the opcode/fd/len/offset/user_data directly from the
 * SQE — values that the internal struct io_kiocb does NOT expose at stable
 * offsets (its layout changes substantially between releases). The trailing
 * fields of the real SQE are not needed and are intentionally omitted.
 */
struct io_uring_sqe_min {
  u8  opcode;     /* 0  : IORING_OP_* */
  u8  flags;      /* 1  : IOSQE_* */
  u16 ioprio;     /* 2  : I/O priority */
  s32 fd;         /* 4  : target file descriptor */
  u64 off;        /* 8  : off / addr2 union */
  u64 addr;       /* 16 : addr / splice_off_in union */
  u32 len;        /* 24 : I/O length in bytes */
  u32 op_flags;   /* 28 : rw_flags / fsync_flags / ... union */
  u64 user_data;  /* 32 : caller correlation token */
  u16 buf_index;  /* 40 : buf_index / buf_group union */
};

/**
 * @brief Capture io_uring SQE fields at request-prep time.
 *
 * Attached to the read/write prep handler, which is invoked through the opcode
 * dispatch table (def->prep) and therefore is not inlined away. It receives the
 * io_kiocb request and the UAPI SQE:
 *
 *   int io_prep_rw(struct io_kiocb *req, const struct io_uring_sqe *sqe)
 *
 * Reading the SQE (stable ABI offsets) yields the opcode, fd, length, offset,
 * priority and user_data. The req->file pointer — the first member of io_kiocb
 * on modern kernels — yields the backing file's inode/device/filesystem so the
 * io_uring I/O can be joined with the fs/VFS trace. Results are staged in
 * io_uring_submit_map keyed by the req pointer and consumed by the SUBMIT and
 * COMPLETE probes. If the prep symbol is unavailable on a given kernel these
 * fields simply stay empty (graceful degradation).
 *
 * @param ctx BPF context
 * @param req io_kiocb request structure pointer (PARM1)
 * @param sqe UAPI io_uring_sqe pointer (PARM2)
 * @return    0
 */
int trace_io_uring_prep_rw(struct pt_regs *ctx, void *req, void *sqe) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  if (!req || !sqe) {
    return 0;
  }

  struct io_uring_sqe_min s = {};
  /* The SQE normally lives in kernel-allocated ring memory (mmapped to
   * userspace), so a kernel read works. With IORING_SETUP_NO_MMAP (6.5+) the
   * ring is allocated in application memory and the pointer is a user address,
   * for which the kernel read fails — fall back to a user read so the SQE
   * fields are still captured. */
  if (bpf_probe_read_kernel(&s, sizeof(s), sqe) != 0) {
    bpf_probe_read_user(&s, sizeof(s), sqe);
  }

  struct io_uring_submit_ctx submit_ctx = {};
  submit_ctx.opcode    = s.opcode;
  submit_ctx.sqe_flags = s.flags;
  submit_ctx.ioprio    = s.ioprio;
  submit_ctx.fd        = s.fd;
  submit_ctx.offset    = s.off;
  submit_ctx.len       = s.len;
  submit_ctx.user_data = s.user_data;
  submit_ctx.buf_index = s.buf_index;

  /* req->file is the first member of struct io_kiocb on modern kernels. Pull
   * the backing file identity when it is a regular file on a real filesystem;
   * is_regular_file() filters sockets/pipes/pseudo-fs and bad reads. */
  struct file *file = NULL;
  bpf_probe_read_kernel(&file, sizeof(file), req);
  if (is_regular_file(file)) {
    submit_ctx.inode = get_file_inode(file);
    get_file_source(file, &submit_ctx.dev, &submit_ctx.fs_magic);
  }

  u64 req_ptr = (u64)req;
  io_uring_submit_map.update(&req_ptr, &submit_ctx);
  return 0;
}

/**
 * @brief Trace io_uring SQE submission (via io_submit_sqes or io_queue_sqe)
 *
 * Captures individual SQE submissions with operation details.
 * Stores submit timestamp for latency calculation on completion.
 *
 * The opcode/fd/len/offset/user_data are read from the SQE by the prep probe
 * (trace_io_uring_prep_rw) and staged in io_uring_submit_map before this probe
 * runs. We reuse that staged context and stamp the submission timestamp so the
 * completion probe can compute latency. When no prep data exists (a non-rw op,
 * or a kernel without the prep symbol) we still recover the backing file from
 * req->file on a best-effort basis.
 *
 * @param ctx BPF context
 * @param req io_kiocb request structure pointer
 * @return    0
 */
int trace_io_uring_submit(struct pt_regs *ctx, void *req) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  u64 req_ptr = (u64)req;

  /* Reuse the SQE context staged by the prep probe; fall back to reading the
   * backing file directly when this request was not prepped through the rw
   * handler (e.g. fsync/openat ops, or a kernel without the prep symbol). */
  struct io_uring_submit_ctx submit_ctx = {};
  struct io_uring_submit_ctx *staged = io_uring_submit_map.lookup(&req_ptr);
  if (staged) {
    submit_ctx = *staged;
  } else {
    submit_ctx.fd = -1;
    struct file *file = NULL;
    bpf_probe_read_kernel(&file, sizeof(file), req);
    if (is_regular_file(file)) {
      submit_ctx.inode = get_file_inode(file);
      get_file_source(file, &submit_ctx.dev, &submit_ctx.fs_magic);
    }
  }
  submit_ctx.submit_ts_ns = ts;
  io_uring_submit_map.update(&req_ptr, &submit_ctx);

  struct io_uring_event_data e = {};
  e.timestamp_ns = ts;
  e.event_type = IOURING_SUBMIT;
  e.pid = pid;
  e.tid = (u32)pid_tgid;
  bpf_get_current_comm(&e.comm, sizeof(e.comm));
  e.cpu = bpf_get_smp_processor_id();
  e.req_ptr = req_ptr;
  e.user_data = submit_ctx.user_data;
  e.opcode = submit_ctx.opcode;
  e.fd = submit_ctx.fd;
  e.len = submit_ctx.len;
  e.offset = submit_ctx.offset;
  e.sqe_flags = submit_ctx.sqe_flags;
  e.ioprio = submit_ctx.ioprio;
  e.buf_index = submit_ctx.buf_index;
  e.inode = submit_ctx.inode;
  e.dev = submit_ctx.dev;
  e.fs_magic = submit_ctx.fs_magic;
  e.submit_ts_ns = ts;

  io_uring_events.perf_submit(ctx, &e, sizeof(e));
  return 0;
}

/**
 * @brief Trace io_uring request completion (via io_req_complete)
 *
 * Captures request completion with result and calculates latency.
 * Correlates with submission using req_ptr.
 *
 * @param ctx    BPF context
 * @param req    io_kiocb request structure pointer
 * @param result Operation result (bytes transferred or -errno)
 * @return       0
 */
int trace_io_uring_complete(struct pt_regs *ctx, void *req, s32 result) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  u64 req_ptr = (u64)req;

  struct io_uring_event_data e = {};
  e.timestamp_ns = ts;
  e.event_type = IOURING_COMPLETE;
  e.pid = pid;
  e.tid = (u32)pid_tgid;
  bpf_get_current_comm(&e.comm, sizeof(e.comm));
  e.cpu = bpf_get_smp_processor_id();
  e.req_ptr = req_ptr;
  e.complete_ts_ns = ts;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
  e.result = result;

  /* Check if result indicates error */
  if (result < 0) {
    e.is_error = 1;
    e.cqe_errno = -result;
  }
#else
  /* On 6.0+ io_req_complete_post() no longer takes the result as a
   * parameter (it lives in req->cqe.res, whose offset is not stable across
   * releases); PARM2 here is issue_flags or garbage. Leave result/is_error
   * unset rather than recording junk. */
#endif

  /* Lookup submission context for latency calculation and correlation */
  struct io_uring_submit_ctx *submit_ctx = io_uring_submit_map.lookup(&req_ptr);
  if (submit_ctx) {
    e.submit_ts_ns = submit_ctx->submit_ts_ns;
    if (submit_ctx->submit_ts_ns) {
      e.latency_ns = ts - submit_ctx->submit_ts_ns;
    }
    e.user_data = submit_ctx->user_data;
    e.opcode = submit_ctx->opcode;
    e.fd = submit_ctx->fd;
    e.len = submit_ctx->len;
    e.offset = submit_ctx->offset;
    e.sqe_flags = submit_ctx->sqe_flags;
    e.ioprio = submit_ctx->ioprio;
    e.buf_index = submit_ctx->buf_index;
    e.inode = submit_ctx->inode;
    e.dev = submit_ctx->dev;
    e.fs_magic = submit_ctx->fs_magic;

    /* Clean up the map entry */
    io_uring_submit_map.delete(&req_ptr);
  }

  io_uring_events.perf_submit(ctx, &e, sizeof(e));
  return 0;
}

/**
 * @brief Trace io_uring async worker execution (io-wq)
 *
 * Captures when a request is executed by an io-wq worker thread
 * instead of inline in io_uring_enter context.
 *
 * @param ctx BPF context
 * @param req io_kiocb request structure pointer
 * @return    0
 */
int trace_io_uring_worker(struct pt_regs *ctx, void *req) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  u64 req_ptr = (u64)req;

  struct io_uring_event_data e = {};
  e.timestamp_ns = bpf_ktime_get_ns();
  e.event_type = IOURING_WORKER;
  e.pid = pid;
  e.tid = (u32)pid_tgid;
  bpf_get_current_comm(&e.comm, sizeof(e.comm));
  e.cpu = bpf_get_smp_processor_id();
  e.req_ptr = req_ptr;
  e.worker_pid = pid;
  e.worker_tid = (u32)pid_tgid;
  e.worker_cpu = bpf_get_smp_processor_id();
  e.is_async = 1;

  /* Try to get submission context for correlation */
  struct io_uring_submit_ctx *submit_ctx = io_uring_submit_map.lookup(&req_ptr);
  if (submit_ctx) {
    e.user_data = submit_ctx->user_data;
    e.opcode = submit_ctx->opcode;
    e.submit_ts_ns = submit_ctx->submit_ts_ns;
    e.fd = submit_ctx->fd;
    e.len = submit_ctx->len;
    e.offset = submit_ctx->offset;
    e.sqe_flags = submit_ctx->sqe_flags;
    e.inode = submit_ctx->inode;
    e.dev = submit_ctx->dev;
    e.fs_magic = submit_ctx->fs_magic;
  }

  io_uring_events.perf_submit(ctx, &e, sizeof(e));
  return 0;
}

/* io_uring tracepoint-based probes - DISABLED
 * 
 * The io_uring tracepoint format varies significantly across kernel versions.
 * Fields like req, opcode, user_data, flags may not exist or have different
 * names/types. The kprobe-based functions above (trace_io_uring_submit,
 * trace_io_uring_complete) provide kernel-version-agnostic fallbacks.
 *
 * To enable on kernels with compatible tracepoints, change #if 0 to #if 1
 * and verify the tracepoint format matches:
 *   cat /sys/kernel/debug/tracing/events/io_uring/io_uring_submit_sqe/format
 */
#if 0
/**
 * @brief Tracepoint probe for io_uring_submit_sqe
 *
 * Uses stable tracepoint interface when available (kernel 5.6+).
 * Provides reliable access to SQE fields.
 */
TRACEPOINT_PROBE(io_uring, io_uring_submit_sqe) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  
  struct io_uring_event_data e = {};
  e.timestamp_ns = ts;
  e.event_type = IOURING_SUBMIT;
  e.pid = pid;
  e.tid = (u32)pid_tgid;
  bpf_get_current_comm(&e.comm, sizeof(e.comm));
  e.cpu = bpf_get_smp_processor_id();
  
  /* Read from tracepoint args - field names may vary by kernel */
  e.req_ptr = (u64)args->req;
  e.opcode = args->opcode;
  e.user_data = args->user_data;
  e.sqe_flags = args->flags;
  e.submit_ts_ns = ts;

  /* Store submission context */
  u64 req_ptr = e.req_ptr;
  struct io_uring_submit_ctx submit_ctx = {};
  submit_ctx.submit_ts_ns = ts;
  submit_ctx.user_data = e.user_data;
  submit_ctx.opcode = e.opcode;
  io_uring_submit_map.update(&req_ptr, &submit_ctx);

  io_uring_events.perf_submit(args, &e, sizeof(e));
  return 0;
}

/**
 * @brief Tracepoint probe for io_uring_complete
 *
 * Uses stable tracepoint interface for completion events.
 */
TRACEPOINT_PROBE(io_uring, io_uring_complete) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u32 config_key = 0;
  u32 *tracer_pid = tracer_config.lookup(&config_key);
  if (tracer_pid && pid == *tracer_pid) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  
  struct io_uring_event_data e = {};
  e.timestamp_ns = ts;
  e.event_type = IOURING_COMPLETE;
  e.pid = pid;
  e.tid = (u32)pid_tgid;
  bpf_get_current_comm(&e.comm, sizeof(e.comm));
  e.cpu = bpf_get_smp_processor_id();
  
  /* Read from tracepoint args */
  e.req_ptr = (u64)args->req;
  e.user_data = args->user_data;
  e.result = args->res;
  e.complete_ts_ns = ts;
  
  if (e.result < 0) {
    e.is_error = 1;
    e.cqe_errno = -e.result;
  }

  /* Lookup submission for latency */
  u64 req_ptr = e.req_ptr;
  struct io_uring_submit_ctx *submit_ctx = io_uring_submit_map.lookup(&req_ptr);
  if (submit_ctx) {
    e.submit_ts_ns = submit_ctx->submit_ts_ns;
    e.latency_ns = ts - submit_ctx->submit_ts_ns;
    e.opcode = submit_ctx->opcode;
    io_uring_submit_map.delete(&req_ptr);
  }

  io_uring_events.perf_submit(args, &e, sizeof(e));
  return 0;
}
#endif /* disabled io_uring tracepoints */
