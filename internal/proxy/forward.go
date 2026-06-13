package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
)

// forwardingBufferSize is the size of the buffer used in io.CopyBuffer (32KB).
const forwardingBufferSize = 32 * 1024

// forwardStats holds byte counts for a single connection.
type forwardStats struct {
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// countingWriter wraps an io.Writer and atomically counts written bytes.
type countingWriter struct {
	w       io.Writer
	counted *atomic.Int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.counted.Add(int64(n))
	return n, err
}

// forwardRequestAndResponse handles one HTTP request-response cycle through the interceptor pipeline.
//
// Pipeline:
//  1. Read HTTP request from the browser TLS connection
//  2. Pass through Interceptor.InterceptRequest (NoOp for this sprint)
//  3. Write complete request (headers + body) to upstream via Request.Write
//  4. Read HTTP response from upstream TLS connection
//  5. Pass through Interceptor.InterceptResponse (NoOp for this sprint)
//  6. Write complete response (headers + body) to browser via Response.Write
//
// A countingWriter wraps the upstream writer so byte counts are accurate
// regardless of Content-Length presence (handles chunked/streaming).
func forwardRequestAndResponse(
	browserConn io.ReadWriter,
	upstreamConn io.ReadWriter,
	interceptor Interceptor,
	stats *forwardStats,
) (int, error) {
	// 1. Read request from browser
	req, err := http.ReadRequest(bufio.NewReader(browserConn))
	if err != nil {
		return 0, fmt.Errorf("reading request from browser: %w", err)
	}

	// 2. Intercept request (NoOp passes through)
	modifiedReq, reqBody, err := interceptor.InterceptRequest(req)
	if err != nil {
		return 0, fmt.Errorf("intercepting request: %w", err)
	}
	if reqBody != nil {
		modifiedReq.Body = reqBody
	}

	// 3. Write complete request (headers + body) to upstream, counting bytes.
	// The countingWriter captures actual bytes written including chunked encoding.
	upWriter := &countingWriter{w: upstreamConn, counted: &stats.bytesIn}
	if err := modifiedReq.Write(upWriter); err != nil {
		return 0, fmt.Errorf("writing request to upstream: %w", err)
	}

	// 4. Read response from upstream
	resp, err := http.ReadResponse(bufio.NewReader(upstreamConn), modifiedReq)
	if err != nil {
		return 0, fmt.Errorf("reading response from upstream: %w", err)
	}

	// 5. Intercept response (NoOp passes through)
	modifiedResp, respBody, err := interceptor.InterceptResponse(resp)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("intercepting response: %w", err)
	}
	if respBody != nil {
		modifiedResp.Body = respBody
	}

	// 6. Write complete response (headers + body) to browser, counting bytes.
	browserWriter := &countingWriter{w: browserConn, counted: &stats.bytesOut}
	if err := modifiedResp.Write(browserWriter); err != nil {
		return modifiedResp.StatusCode, fmt.Errorf("writing response to browser: %w", err)
	}

	return modifiedResp.StatusCode, nil
}
