#!/usr/bin/env bash
set -u
cd /root/rootkat
. tests/qemu/lib.sh

echo "=== inet_diag / sk_diag related symbols ==="
grep -E "(inet_sk_diag|inet_diag.*fill|inet_csk_diag|sk_diag_fill|inet_diag_dump)" \
    /proc/kallsyms | head -30

echo
echo "=== ftrace-traceable subset (in available_filter_functions) ==="
grep -E "(inet_sk_diag|inet_diag.*fill|inet_csk_diag|sk_diag_fill|inet_diag_dump)" \
    /sys/kernel/debug/tracing/available_filter_functions | head -30

echo
echo "=== specifically: inet_sk_diag_fill ==="
grep -E "\binet_sk_diag_fill\b" /proc/kallsyms || echo "(not in kallsyms)"
grep -E "\binet_sk_diag_fill\b" /sys/kernel/debug/tracing/available_filter_functions \
    || echo "(not ftrace-traceable)"

echo
echo "passed: 0"
echo "failed: 0"
