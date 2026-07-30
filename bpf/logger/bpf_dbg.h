// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>

#include <common/globals.h>
#include <common/pin_internal.h>
#include <common/scratch_mem.h>

typedef struct log_info {
    u64 pid;
    unsigned char log[80];
    unsigned char comm[20];
    u8 _pad[4];
} log_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 15);
    __uint(pinning, OBI_PIN_INTERNAL);
} debug_events SEC(".maps");

enum bpf_func_id___x {
    BPF_FUNC_snprintf___x = 42, /* avoid zero */
    BPF_FUNC_trace_vprintk___x = 177,
};

// Scratch memory, not a bpf_ringbuf_reserve() record: is_spillable_regtype() gained
// PTR_TO_MEM only in 744ea4e3885e (5.11, backported to 5.10.y), so on older kernels the
// reserved pointer reloads from the stack as a scalar once the helper calls below force a
// spill. A map value pointer spills correctly.
SCRATCH_MEM_TYPED(log_info, log_info_t);

#define bpf_dbg_printk(fmt, args...)                                                               \
    do {                                                                                           \
        if (!g_bpf_debug) {                                                                        \
            break;                                                                                 \
        }                                                                                          \
        bpf_printk(fmt, ##args);                                                                   \
        log_info_t *__trace__ = log_info_mem();                                                    \
        if (!__trace__) {                                                                          \
            break;                                                                                 \
        }                                                                                          \
        if (bpf_core_enum_value_exists(enum bpf_func_id___x, BPF_FUNC_snprintf___x)) {             \
            /* snprintf is available: Include the function name and the formatted message */       \
            /* we use __FUNCTION__  and " [%s]" to append the function name to the log   */        \
            BPF_SNPRINTF((char *)__trace__->log,                                                   \
                         sizeof(__trace__->log),                                                   \
                         fmt " [%s]",                                                              \
                         ##args,                                                                   \
                         __FUNCTION__);                                                            \
        } else {                                                                                   \
            __builtin_memcpy(__trace__->log, fmt, sizeof(__trace__->log));                         \
        }                                                                                          \
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();                   \
        __trace__->pid = (u32)BPF_CORE_READ(task, pid);                                            \
        BPF_CORE_READ_STR_INTO(&__trace__->comm, task, comm);                                      \
        bpf_ringbuf_output(&debug_events, __trace__, sizeof(*__trace__), 0);                       \
    } while (0)

#define bpf_dbg_enter() bpf_dbg_printk("%s entered", __FUNCTION__)
#define bpf_dbg_return() bpf_dbg_printk("%s returning", __FUNCTION__)

#define bpf_d_printk(fmt, args...)                                                                 \
    do {                                                                                           \
        if (!g_bpf_debug) {                                                                        \
            break;                                                                                 \
        }                                                                                          \
        bpf_printk(fmt, ##args);                                                                   \
    } while (0)
