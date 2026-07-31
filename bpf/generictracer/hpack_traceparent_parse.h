// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/utils.h>

#include <common/h2_defs.h>
#include <common/h2_tp_huffman.h>
#include <common/tp_info.h>
#include <common/trace_util.h>

static __always_inline u8 try_parse_tp_value(const unsigned char *val, tp_info_t *tp) {
    if (val[k_tp_val_dash1] != '-' || val[k_tp_val_dash2] != '-' || val[k_tp_val_dash3] != '-') {
        return 0;
    }
    decode_hex(tp->trace_id, &val[k_tp_val_trace_id_start], TRACE_ID_SIZE_BYTES * 2);
    decode_hex(tp->parent_id, &val[k_tp_val_span_id_start], SPAN_ID_SIZE_BYTES * 2);
    tp->flags = 1;
    return 1;
}

static const u8 k_hex_chars[256] = {
    ['0' ... '9'] = 1,
    ['a' ... 'f'] = 1,
    ['A' ... 'F'] = 1,
};

// Locates a compressed value with no name to match, kept apart from the plain
// scan so neither program carries two heavy loops
static __always_inline u8 find_hpack_traceparent_huffman(const unsigned char *data,
                                                         u32 data_len,
                                                         h2_tp_huff_candidate_t *huff) {
    huff->at = 0;
    huff->len = 0;

    if (data_len < (u32)k_h2_tp_huff_min + 1) {
        return 0;
    }

    const u32 max_pos = data_len - (u32)k_h2_tp_huff_min - 1;

    for (u16 i = 0; i < k_hpack_tp_max_scan && i <= max_pos; i++) {
        if (h2_tp_huff_len_plausible(data[i])) {
            huff->at = (u16)(i + 1);
            huff->len = (u8)(data[i] & (u8)~k_hpack_huffman_flag);
            return 1;
        }
    }

    return 0;
}

// Recovers a plain traceparent value when the HPACK name reference is a dyn-table index
static __always_inline u8 find_hpack_traceparent_value(const unsigned char *data,
                                                       u32 data_len,
                                                       tp_info_t *tp) {
    if (data_len < (u32)k_hpack_value_len_tp + 1) {
        return 0;
    }

    const u32 max_pos = data_len - (u32)k_hpack_value_len_tp - 1;

    for (u16 i = 0; i < k_hpack_tp_max_scan && i <= max_pos; i++) {
        if (data[i] != k_hpack_value_len_tp) {
            continue;
        }

        const unsigned char *val = &data[i + 1];
        if (val[0] != '0' || val[1] != '0' || val[2] != '-') {
            continue;
        }
        if (val[k_tp_val_dash2] != '-' || val[k_tp_val_dash3] != '-') {
            continue;
        }
        // weak evidence without a name match — spot-check id edges for hex
        const u8 ok = k_hex_chars[val[k_tp_val_trace_id_start]] &
                      k_hex_chars[val[k_tp_val_trace_id_start + 1]] &
                      k_hex_chars[val[k_tp_val_dash2 - 2]] & k_hex_chars[val[k_tp_val_dash2 - 1]] &
                      k_hex_chars[val[k_tp_val_span_id_start]] &
                      k_hex_chars[val[k_tp_val_span_id_start + 1]] &
                      k_hex_chars[val[k_tp_val_dash3 - 2]] & k_hex_chars[val[k_tp_val_dash3 - 1]];
        if (!ok) {
            continue;
        }

        return try_parse_tp_value(val, tp);
    }

    return 0;
}

// w and out are the caller's map-value scratch buffers
static __always_inline u8 try_parse_tp_huffman_value(const unsigned char *data,
                                                     u32 data_len,
                                                     const h2_tp_huff_candidate_t *huff,
                                                     unsigned char *w,
                                                     unsigned char *out,
                                                     tp_info_t *tp) {
    u32 val_at = huff->at;
    const u32 vlen = huff->len;

    bpf_clamp_umax(val_at, k_h2_tp_huff_at_max);

    if (!vlen || val_at + vlen > data_len) {
        return 0;
    }

    // zeroed past the value: it can be the block's last field, and lookahead reads past it
    bpf_memset(w, 0, k_h2_tp_huff_window);

    // the floor is guaranteed by the check above, so only the tail needs a bound test
    bpf_memcpy(w, data + val_at, k_h2_tp_huff_min);
    for (u32 i = k_h2_tp_huff_min; i < k_h2_tp_huff_max; i++) {
        const u32 at = val_at + i;
        w[i] = at < data_len ? data[at] : 0;
    }

    if (!h2_huff_decode_tp(w, vlen, out)) {
        return 0;
    }

    return try_parse_tp_value(out, tp);
}

// Name-fingerprint scan (plain + huffman)
static __always_inline u8 parse_hpack_traceparent(const unsigned char *data,
                                                  u32 data_len,
                                                  tp_info_t *tp,
                                                  h2_tp_huff_candidate_t *huff) {
    huff->at = 0;
    huff->len = 0;

    // bounded by the smallest field worth recognizing; each shape re-checks its own length
    if (data_len >= k_h2_tp_hpack_huff_min) {
        const u32 max_pos = data_len - k_h2_tp_hpack_huff_min;

        for (u16 i = 0; i < k_hpack_tp_max_scan && i <= max_pos; i++) {
            // senders that index the name emit any of the three literal forms
            if (!h2_hpack_is_literal(data[i])) {
                continue;
            }

            const u8 name_len_byte = data[i + 1];

            if (name_len_byte == k_hpack_tp_name_len) {
                if (i + k_hpack_tp_val_offset > data_len) {
                    continue;
                }
                if (bpf_memcmp(&data[i + k_hpack_tp_name_offset],
                               k_hpack_tp_name,
                               k_hpack_tp_name_len) != 0) {
                    continue;
                }
                const u8 vlb = data[i + k_hpack_tp_name_offset + k_hpack_tp_name_len];
                if (vlb == k_hpack_value_len_tp) {
                    if (i + k_h2_tp_hpack_size > data_len) {
                        continue;
                    }
                    return try_parse_tp_value(&data[i + k_hpack_tp_val_offset], tp);
                }
                if (h2_tp_huff_len_plausible(vlb)) {
                    huff->at = (u16)(i + k_hpack_tp_val_offset);
                    huff->len = (u8)(vlb & (u8)~k_hpack_huffman_flag);
                    return 0;
                }
                continue;
            }

            if (name_len_byte == (k_hpack_tp_name_huffman_len | 0x80)) {
                if (i + k_hpack_tp_val_offset_huffman > data_len) {
                    continue;
                }
                if (bpf_memcmp(&data[i + k_hpack_tp_name_offset],
                               k_hpack_tp_huffman,
                               k_hpack_tp_name_huffman_len) != 0) {
                    continue;
                }
                const u8 vlb = data[i + k_hpack_tp_name_offset + k_hpack_tp_name_huffman_len];
                if (vlb == k_hpack_value_len_tp) {
                    if (i + k_h2_tp_hpack_huffman_size > data_len) {
                        continue;
                    }
                    return try_parse_tp_value(&data[i + k_hpack_tp_val_offset_huffman], tp);
                }
                if (h2_tp_huff_len_plausible(vlb)) {
                    huff->at = (u16)(i + k_hpack_tp_val_offset_huffman);
                    huff->len = (u8)(vlb & (u8)~k_hpack_huffman_flag);
                    return 0;
                }
                continue;
            }
        }
    }

    return 0;
}
