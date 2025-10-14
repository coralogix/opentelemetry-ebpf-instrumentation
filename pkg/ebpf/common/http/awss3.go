// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"go.opentelemetry.io/obi/pkg/app/request"
)

func AWSS3Span(baseSpan *request.Span, req *http.Request, _ *http.Response) (request.Span, bool) {
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			fmt.Println("Error reading body:", err)
		} else {
			fmt.Println("Body:", string(bodyBytes))
			// Restore the body for further use
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	} else {
		fmt.Println("No body in request")
	}

	return *baseSpan, true
}
