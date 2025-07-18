// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// This implementation copied from https://github.com/open-telemetry/opentelemetry-go-instrumentation/blob/main/internal/include/otel_types.h
// and has been adapted to OBI.

#ifndef _OTEL_TYPES_H
#define _OTEL_TYPES_H

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>

#include <logger/bpf_dbg.h>

volatile const u64 attr_type_invalid;

volatile const u64 attr_type_bool;
volatile const u64 attr_type_int64;
volatile const u64 attr_type_float64;
volatile const u64 attr_type_string;

volatile const u64 attr_type_boolslice;
volatile const u64 attr_type_int64slice;
volatile const u64 attr_type_float64slice;
volatile const u64 attr_type_stringslice;

static __always_inline bool set_attr_value(otel_attirbute_t *attr,
                                           go_otel_attr_value_t *go_attr_value) {
    u64 vtype = go_attr_value->vtype;

    // Constant size values
    if (vtype == attr_type_bool || vtype == attr_type_int64 || vtype == attr_type_float64) {
        bpf_probe_read(attr->value, sizeof(s64), &go_attr_value->numeric);
        return true;
    }

    // String values
    if (vtype == attr_type_string) {
        if (go_attr_value->string.len >= OTEL_ATTRIBUTE_VALUE_MAX_LEN) {
            bpf_printk("Aattribute string value is too long\n");
            return false;
        }
        long res =
            bpf_probe_read_user(attr->value,
                                go_attr_value->string.len & (OTEL_ATTRIBUTE_VALUE_MAX_LEN - 1),
                                go_attr_value->string.str);
        return res == 0;
    }

    // TODO (#525): handle slices
    return false;
}

static __always_inline void
convert_go_otel_attributes(void *attrs_buf, u64 slice_len, otel_attributes_t *enc_attrs) {
    if (attrs_buf == NULL) {
        return;
    }

    if (slice_len < 1) {
        return;
    }

    go_otel_key_value_t *go_attr = (go_otel_key_value_t *)attrs_buf;
    go_otel_attr_value_t go_attr_value = {0};
    struct go_string go_str = {0};
    u8 valid_attrs = enc_attrs->valid_attrs;
    if (valid_attrs >= OTEL_ATTRUBUTE_MAX_COUNT) {
        return;
    }

    for (u8 go_attr_index = 0; go_attr_index < OTEL_ATTRUBUTE_MAX_COUNT; go_attr_index++) {
        if (go_attr_index >= slice_len) {
            break;
        }
        __builtin_memset(&go_attr_value, 0, sizeof(go_otel_attr_value_t));
        // Read the value struct
        bpf_probe_read(&go_attr_value, sizeof(go_otel_attr_value_t), &go_attr[go_attr_index].value);

        if (go_attr_value.vtype == attr_type_invalid) {
            continue;
        }

        // Read the key string
        bpf_probe_read(&go_str, sizeof(struct go_string), &go_attr[go_attr_index].key);
        if (go_str.len >= OTEL_ATTRIBUTE_KEY_MAX_LEN) {
            // key string is too large
            bpf_dbg_printk("Attribute key string is too long\n");
            continue;
        }

        // Need to check valid_attrs otherwise the ebpf verifier thinks it's possible to exceed
        // the max register value for a downstream call, even though it's not possible with
        // this same check at the end of the loop.
        if (valid_attrs >= OTEL_ATTRUBUTE_MAX_COUNT) {
            break;
        }

        bpf_probe_read_user(enc_attrs->attrs[valid_attrs].key,
                            go_str.len & (OTEL_ATTRIBUTE_KEY_MAX_LEN - 1),
                            go_str.str);

        if (!set_attr_value(&enc_attrs->attrs[valid_attrs], &go_attr_value)) {
            continue;
        }

        enc_attrs->attrs[valid_attrs].vtype = go_attr_value.vtype;
        valid_attrs++;
        if (valid_attrs >= OTEL_ATTRUBUTE_MAX_COUNT) {
            // No more space for attributes
            break;
        }
    }

    enc_attrs->valid_attrs = valid_attrs;
}

#endif
