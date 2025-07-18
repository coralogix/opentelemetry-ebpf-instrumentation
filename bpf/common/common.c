//go:build obi_bpf_ignore
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

#include <common/common.h>

// Force emitting struct http_request_trace into the ELF for automatic creation of Golang struct
const http_request_trace *unused_4 __attribute__((unused));
const sql_request_trace *unused_3 __attribute__((unused));
const tcp_req_t *unused_5 __attribute__((unused));
const kafka_client_req_t *unused_6 __attribute__((unused));
const redis_client_req_t *unused_7 __attribute__((unused));
const kafka_go_req_t *unused_8 __attribute__((unused));
const tcp_large_buffer_t *unused_9 __attribute__((unused));
const otel_span_t *unused_10 __attribute__((unused));
