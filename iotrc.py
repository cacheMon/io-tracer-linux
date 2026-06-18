#!/usr/bin/env python3
"""
IO Tracer - A Linux I/O syscall tracing utility.

This module serves as the entry point for the IO Tracer application, which
traces file system, block device, and cache I/O operations on Linux
systems using eBPF/BPF technology.

Usage:
    python iotrc.py [OPTIONS]
    python iotrc.py dev [DEV OPTIONS]

Subcommands:
    dev                       Run in developer mode with extra logs and checks

Options:
    -v, --verbose             Print verbose output
    -a, --anonimize           Enable anonymization of process and file names
    --cache                   Enable page-cache event tracing (higher overhead).
                              Auto-enabled when the host has enough CPU and DRAM.
    --network                 Enable network event tracing — connection
                              lifecycle, epoll, sockopt, drops. Auto-enabled when
                              the host has enough CPU, DRAM and network.
    --computer-id             Print this machine ID and exit
    --reward                  Show your reward code (unlocked after uploading traces)
    --no-upload               Disable automatic upload of traces

Dev Options (only available with 'dev' subcommand):
    --trace-bucket NAME       Override upload bucket name (default: linux_v1)

Examples:
    # Run with default settings
    python iotrc.py

    # Run in developer mode
    python iotrc.py dev

    # Run in developer mode with custom bucket
    python iotrc.py dev --trace-bucket my_bucket

    # Print machine ID
    python iotrc.py --computer-id

    # Check reward status
    python iotrc.py --reward
"""

import argparse
import os
import resource
import sys
import tempfile

from src.tracer.IOTracer import IOTracer
from src.utility.utils import (
    auto_select_tracing,
    capture_machine_id,
    get_reward_code,
    is_reward_unlocked,
)


def maximize_fd_limit():
    """Attempt to maximize the file descriptor open limit."""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = 1048576
        if hard != resource.RLIM_INFINITY:
            target = min(target, hard)
        # Sudo often drops the soft limit to 1024. Elevate it back up.
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: IO Tracer must be run with sudo or as root.")
        sys.exit(1)

    maximize_fd_limit()
    app_version = "vRelease"

    parser = argparse.ArgumentParser(description='Trace IO syscalls')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print verbose output')
    parser.add_argument('-a', '--anonimize', action='store_true', help='Enable anonymization of process and file names')
    parser.add_argument('--cache', action='store_true', help='Force-enable page-cache event tracing (higher overhead; otherwise auto-enabled when the host has enough CPU and DRAM)')
    parser.add_argument('--network', action='store_true', help='Force-enable network event tracing: connection lifecycle, epoll, sockopt, drops (otherwise auto-enabled when the host has enough CPU, DRAM and network)')
    parser.add_argument('--computer-id', action='store_true', help='Print this machine ID and exit')
    parser.add_argument('--reward', action='store_true', help='Show your reward code (unlocked after uploading traces)')
    parser.add_argument('--no-upload', action='store_true', help='Disable automatic upload of traces (for testing)')

    subparsers = parser.add_subparsers(dest='subcommand')
    dev_parser = subparsers.add_parser('dev', help='Run in developer mode with extra logs and checks')
    dev_parser.add_argument('-v', '--verbose', action='store_true', help='Print verbose output')
    dev_parser.add_argument('-a', '--anonimize', action='store_true', help='Enable anonymization of process and file names')
    dev_parser.add_argument('--cache', action='store_true', help='Force-enable page-cache event tracing (higher overhead; otherwise auto-enabled when the host has enough CPU and DRAM)')
    dev_parser.add_argument('--network', action='store_true', help='Force-enable network event tracing: connection lifecycle, epoll, sockopt, drops (otherwise auto-enabled when the host has enough CPU, DRAM and network)')
    dev_parser.add_argument('--no-upload', action='store_true', help='Disable automatic upload of traces (for testing)')
    dev_parser.add_argument('--trace-bucket', type=str, default=None, help='Override upload bucket name (default: linux_v1)')

    parse_args = parser.parse_args()
    output_dir = tempfile.gettempdir()

    # Handle --computer-id flag: print machine ID and exit
    if parse_args.computer_id:
        print(f"Here is your computer ID: {capture_machine_id().upper()}")
        exit(0)

    # Handle --reward flag: show reward code if available
    if parse_args.reward:
        reward_code = get_reward_code()
        if reward_code:
            print(f"Your Prolific submissions code: {reward_code}")
        else:
            print("Reward not yet unlocked. Upload at least one trace to complete your submission!")
        exit(0)

    developer_mode = parse_args.subcommand == 'dev'
    verbose = parse_args.verbose
    anonimize = parse_args.anonimize
    no_upload = parse_args.no_upload
    trace_cache = parse_args.cache
    trace_network = parse_args.network
    trace_bucket = parse_args.trace_bucket if developer_mode else None

    # Auto-enable the higher-overhead cache/network probes when the host has
    # enough CPU, DRAM and network headroom. Explicit --cache/--network flags
    # are always honored; this only switches a subsystem on, never off.
    trace_cache, trace_network = auto_select_tracing(
        trace_cache, trace_network, verbose=verbose
    )

    # Initialize and start the IO tracer
    tracer = IOTracer(
        output_dir=output_dir,
        bpf_file='./src/tracer/prober/prober.c',
        page_cnt=8,
        verbose=verbose,
        anonymous=anonimize,
        automatic_upload=not no_upload,
        developer_mode=developer_mode,
        version=app_version,
        trace_bucket=trace_bucket,
        trace_cache=trace_cache,
        trace_network=trace_network,
    )
    tracer.trace()
