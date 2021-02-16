#! /usr/bin/python2
# @lint-avoid-python-3-compatibility-imports
#
# cputasks  Summarize the tasks using a CPU core.
#
# This measures how long each task runs on each CPU core and prints a table of
# the results.
#
# Adapted from cpudist by Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from collections import defaultdict
from time import sleep
import argparse
import time


bpf_text = """#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef struct cpu_pid_key {
    u32 cpu;
    u64 pid;
} cpu_pid_key_t;


BPF_HASH(start, u32, u64);
BPF_HASH(runtimes, cpu_pid_key_t, u64);

static inline void update_runtime(u32 cpu, u32 tgid, u32 pid, u64 ts)
{
    u64 *tsp = start.lookup(&pid);
    if (tsp == 0)
        return;

    if (ts < *tsp) {
        // Probably a clock issue where the recorded on-CPU event had a
        // timestamp later than the recorded off-CPU event, or vice versa.
        return;
    }
    u64 delta = ts - *tsp;
    FACTOR

    u64 new_total = delta;
    cpu_pid_key_t key = {.cpu = cpu, .pid = tgid};
    u64 *old_total = runtimes.lookup(&key);
    if (old_total != 0) {
        new_total += *old_total;
    }
    
    runtimes.update(&key, &new_total);
}

int sched_switch(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;

    if (prev->state == TASK_RUNNING) {
        u32 prev_pid = prev->pid;
        u32 prev_tgid = prev->tgid;
        u32 cpu = prev->cpu;

        if (FILTER) {
            update_runtime(cpu, prev_tgid, prev_pid, ts);
        }
    }

    start.update(&pid, &ts);

    return 0;
}
"""


def main(args):
    global bpf_text

    countdown = args.count
    if args.milliseconds:
        bpf_text = bpf_text.replace("FACTOR", "delta /= 1000000;")
        unit = "ms"
        factor = 1000
    else:
        bpf_text = bpf_text.replace("FACTOR", "delta /= 1000;")
        unit = "us"
        factor = 1000000
    if args.cpu:
        bpf_text = bpf_text.replace("FILTER", "cpu == {}".format(args.cpu))
    else:
        bpf_text = bpf_text.replace("FILTER", "1")

    b = BPF(text=bpf_text)
    b.attach_kprobe(event="finish_task_switch", fn_name="sched_switch")

    print("Tracing on-CPU time... Hit Ctrl-C to end.")

    exiting = 0 if args.interval else 1
    runtimes = b["runtimes"]
    while 1:
        start = time.time()
        try:
            sleep(int(args.interval))
        except KeyboardInterrupt:
            exiting = 1
        wall_time = (time.time() - start) * factor

        by_cpu = defaultdict(dict)
        for k, v in runtimes.items():
            by_cpu[k.cpu][k.pid] = v

        for cpu, cputimes in by_cpu.items():
            print_runtimes(cpu, cputimes, wall_time, unit)

        runtimes.clear()

        countdown -= 1
        if exiting or countdown == 0:
            exit()


def print_runtimes(cpu, runtimes, wall_time, unit):
    header = "{:>7}  {:<15} : {:>9}  {:>7}  {:>7}"
    body = "{:>7}  {:<15} : {:>9}  {:>7.2%}  {:>7.2%}  {}"
    max_bar = 21

    runtime_max, runtime_tot = 0, 0
    for runtime in runtimes.values():
        runtime_tot += runtime.value
        if runtime.value > runtime_max:
            runtime_max = runtime.value

    pidle = 1 - (runtime_tot / float(wall_time))
    print("\n\ncpu {}  [{:.2%} idle]\n".format(cpu, pidle))

    print(header.format("pid", "comm", "time ({})".format(unit), "%active", "%wall"))

    def pid_to_comm(pid):
        try:
            return open("/proc/%d/comm" % pid, "r").read().strip()
        except IOError:
            return ""

    for pid, runtime in sorted(
        runtimes.items(), key=lambda x: x[1].value, reverse=True
    ):
        pactive = runtime.value / float(runtime_tot)
        pwall = runtime.value / float(wall_time)
        bar = "*" * int(pwall * max_bar)
        print(body.format(pid, pid_to_comm(pid), runtime.value, pactive, pwall, bar))


if __name__ == "__main__":
    examples = """examples:
        cputasks              # trace which processes used which CPUs for how long
        cputasks 1 10         # print 1 second summaries, 10 times
        cputasks -m           # times in milliseconds
        cputasks -c 8         # trace CPU 8 only
    """
    parser = argparse.ArgumentParser(
        description="Summarize the tasks using a CPU core.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples,
    )
    parser.add_argument(
        "-m", "--milliseconds", action="store_true", help="millisecond histogram"
    )
    parser.add_argument("-c", "--cpu", help="trace this CPU only")
    parser.add_argument(
        "interval",
        nargs="?",
        type=int,
        default=99999999,
        help="output interval, in seconds",
    )
    parser.add_argument(
        "count", nargs="?", type=int, default=99999999, help="number of outputs"
    )
    args = parser.parse_args()

    main(args)
