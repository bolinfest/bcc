#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# opensnoop Trace open() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: opensnoop [-h] [-T] [-x] [-p PID] [-d DURATION] [-t TID] [-n NAME]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 17-Sep-2015   Brendan Gregg   Created this.
# 29-Apr-2016   Allan McAleavy  Updated for BPF_PERF_OUTPUT.
# 08-Oct-2016   Dina Goldshtein Support filtering by PID and TID.

from __future__ import print_function
from bcc import ArgString, BPF
import argparse
import ctypes as ct
from datetime import datetime, timedelta

# arguments
examples = """examples:
    ./opensnoop           # trace all open() syscalls
    ./opensnoop -T        # include timestamps
    ./opensnoop -x        # only show failed opens
    ./opensnoop -p 181    # only trace PID 181
    ./opensnoop -t 123    # only trace TID 123
    ./opensnoop -d 10     # trace for 10 seconds only
    ./opensnoop -n main   # only print process names containing "main"
"""
parser = argparse.ArgumentParser(
    description="Trace open() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-x", "--failed", action="store_true",
    help="only show failed opens")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-t", "--tid",
    help="trace this TID only")
parser.add_argument("-d", "--duration",
    help="total duration of trace in seconds")
parser.add_argument("-n", "--name",
    type=ArgString,
    help="only print process names containing this name")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct val_t {
    u64 id;
    u64 ts;
    char comm[TASK_COMM_LEN];
    const char *fname;
};

struct data_t {
    u64 id;
    u64 ts;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};

// If a[0] == 0, then there is nothing to filter.
// If a[0] == 1, then filter by the pid in a[1].
// If a[0] == 2, then filter by the tid in a[2].
// TODO(mbolin): Use a single u64 to store this data.
BPF_ARRAY(filter, u32, 3);

BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(events);

int trace_entry(struct pt_regs *ctx, int dfd, const char __user *filename)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part

    u32 zero_index = 0;
    u32 one_index = 1;
    u32 two_index = 2;

    u32 zero = 0;
    u32 *filter_index = filter.lookup_or_init(&zero_index, &zero);

    if (*filter_index == 1) {
        u32 *filter_pid = filter.lookup_or_init(&one_index, &zero);
        if (pid != *filter_pid) {
            return 0;
        }
    } else if (*filter_index == 2) {
        u32 *filter_tid = filter.lookup_or_init(&two_index, &zero);
        if (tid != *filter_tid) {
            return 0;
        }
    }

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.ts = bpf_ktime_get_ns();
        val.fname = filename;
        infotmp.update(&id, &val);
    }

    return 0;
};

int trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};

    u64 tsp = bpf_ktime_get_ns();

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.id = valp->id;
    data.ts = tsp / 1000;
    data.ret = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);

    return 0;
}
"""

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text, debug=0)

if args.tid:
    b["filter"][ct.c_int(0)] = ct.c_int(2)
    b["filter"][ct.c_int(1)] = ct.c_int(0)
    b["filter"][ct.c_int(2)] = ct.c_int(int(args.tid))
elif args.pid:
    b["filter"][ct.c_int(0)] = ct.c_int(1)
    b["filter"][ct.c_int(1)] = ct.c_int(int(args.pid))
    b["filter"][ct.c_int(2)] = ct.c_int(0)
else:
    b["filter"][ct.c_int(0)] = ct.c_int(0)
    b["filter"][ct.c_int(1)] = ct.c_int(0)
    b["filter"][ct.c_int(2)] = ct.c_int(0)

b.attach_kprobe(event="do_sys_open", fn_name="trace_entry")
b.attach_kretprobe(event="do_sys_open", fn_name="trace_return")

TASK_COMM_LEN = 16    # linux/sched.h
NAME_MAX = 255        # linux/limits.h

class Data(ct.Structure):
    _fields_ = [
        ("id", ct.c_ulonglong),
        ("ts", ct.c_ulonglong),
        ("ret", ct.c_int),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("fname", ct.c_char * NAME_MAX)
    ]

initial_ts = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
print("%-6s %-16s %4s %3s %s" %
      ("TID" if args.tid else "PID", "COMM", "FD", "ERR", "PATH"))

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    global initial_ts

    # split return value into FD and errno columns
    if event.ret >= 0:
        fd_s = event.ret
        err = 0
    else:
        fd_s = -1
        err = - event.ret

    if not initial_ts:
        initial_ts = event.ts

    if args.failed and (event.ret >= 0):
        return

    if args.name and bytes(args.name) not in event.comm:
        return

    if args.timestamp:
        delta = event.ts - initial_ts
        print("%-14.9f" % (float(delta) / 1000000), end="")

    print("%-6d %-16s %4d %3d %s" %
          (event.id & 0xffffffff if args.tid else event.id >> 32,
           event.comm.decode(), fd_s, err, event.fname.decode()))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
start_time = datetime.now()
while not args.duration or datetime.now() - start_time < args.duration:
    b.perf_buffer_poll()
