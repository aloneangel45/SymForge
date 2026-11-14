// Package mcpserver implements SymForge's Model Context Protocol (MCP) server
// over both stdio (auto-detecting NDJSON and Content-Length framing) and
// loopback-guarded Streamable HTTP / SSE transports.
package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aloneangel45/symforge/pkg/analyzer"
)

const maxFrameBytes = 16 * 1024 * 1024

// Server serves SymForge forensic MCP tools over stdio or HTTP.
type Server struct {
	version string
	engine  *analyzer.Engine

	sseMu    sync.Mutex
	sessions map[string]chan []byte
}

// New creates a new SymForge MCP server bound to engine.
func New(version string, engine *analyzer.Engine) *Server {
	if version == "" {
		version = "1.0.1"
	}
	if engine == nil {
		engine = analyzer.DefaultEngine
	}
	return &Server{
		version:  version,
		engine:   engine,
		sessions: make(map[string]chan []byte),
	}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type frameMode int

const (
	frameNDJSON frameMode = iota
	frameContentLength
)

// ServeStdio processes MCP JSON-RPC messages from r and writes responses to w until EOF or ctx cancellation.
func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var writeMu sync.Mutex

	writeFrame := func(mode frameMode, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if mode == frameContentLength {
			header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(payload))
			if _, err := io.WriteString(w, header); err != nil {
				return err
			}
			_, err := w.Write(payload)
			return err
		}
		if _, err := w.Write(payload); err != nil {
			return err
		}
		_, err := w.Write([]byte("\n"))
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		raw, mode, err := readNextMessage(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}

		respBytes, hasResp := s.handleRawJSON(raw)
		if !hasResp {
			continue
		}
		if err := writeFrame(mode, respBytes); err != nil {
			return err
		}
	}
}

func readNextMessage(br *bufio.Reader) ([]byte, frameMode, error) {
	for {
		b, err := br.Peek(1)
		if err != nil {
			return nil, frameNDJSON, err
		}
		if b[0] == '\r' || b[0] == '\n' || b[0] == ' ' || b[0] == '\t' {
			_, _ = br.ReadByte()
			continue
		}
		break
	}

	peek, _ := br.Peek(16)
	if len(peek) >= 15 && strings.EqualFold(string(peek[:15]), "Content-Length:") {
		contentLen := -1
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return nil, frameContentLength, err
			}
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed == "" {
				break
			}
			if idx := strings.IndexByte(trimmed, ':'); idx > 0 {
				k := strings.TrimSpace(trimmed[:idx])
				v := strings.TrimSpace(trimmed[idx+1:])
				if strings.EqualFold(k, "Content-Length") {
					n, perr := strconv.Atoi(v)
					if perr != nil || n < 0 || n > maxFrameBytes {
						return nil, frameContentLength, fmt.Errorf("invalid Content-Length %q", v)
					}
					contentLen = n
				}
			}
		}
		if contentLen < 0 {
			return nil, frameContentLength, fmt.Errorf("missing Content-Length header")
		}
		buf := make([]byte, contentLen)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, frameContentLength, err
		}
		return buf, frameContentLength, nil
	}

	var lineBuf bytes.Buffer
	for {
		chunk, isPrefix, err := br.ReadLine()
		if len(chunk) > 0 {
			if lineBuf.Len()+len(chunk) > maxFrameBytes {
				return nil, frameNDJSON, fmt.Errorf("JSON-RPC line exceeds %d bytes", maxFrameBytes)
			}
			lineBuf.Write(chunk)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && lineBuf.Len() > 0 {
				return lineBuf.Bytes(), frameNDJSON, nil
			}
			return nil, frameNDJSON, err
		}
		if !isPrefix {
			break
		}
	}
	return lineBuf.Bytes(), frameNDJSON, nil
}

func (s *Server) handleRawJSON(raw []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		resp := rpcResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error:   &rpcError{Code: -32700, Message: "Parse error: empty JSON payload"},
		}
		out, _ := json.Marshal(resp)
		return out, true
	}

	// JSON-RPC 2.0 batch request array [...]
	if trimmed[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			resp := rpcResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &rpcError{Code: -32700, Message: "Parse error: " + err.Error()},
			}
			out, _ := json.Marshal(resp)
			return out, true
		}
		if len(batch) == 0 {
			resp := rpcResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &rpcError{Code: -32600, Message: "Invalid Request: empty batch"},
			}
			out, _ := json.Marshal(resp)
			return out, true
		}
		var replies []rpcResponse
		for _, elem := range batch {
			if r, ok := s.handleSingleRequest(elem); ok {
				replies = append(replies, r)
			}
		}
		if len(replies) == 0 {
			return nil, false
		}
		out, _ := json.Marshal(replies)
		return out, true
	}

	resp, ok := s.handleSingleRequest(trimmed)
	if !ok {
		return nil, false
	}
	out, _ := json.Marshal(resp)
	return out, true
}

func (s *Server) handleSingleRequest(raw []byte) (rpcResponse, bool) {
	var req rpcRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error:   &rpcError{Code: -32700, Message: "Parse error: " + err.Error()},
		}, true
	}

	idRaw := bytes.TrimSpace(req.ID)
	// Per JSON-RPC 2.0: a Notification omits the "id" member entirely (len(idRaw) == 0).
	// An explicit `"id": null` is NOT a notification and must receive a response with `"id": null`.
	if len(idRaw) == 0 {
		if req.Method == "" {
			return rpcResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &rpcError{Code: -32600, Message: "Invalid Request: missing method"},
			}, true
		}
		return rpcResponse{}, false
	}

	if req.Method == "" {
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      decodeIDValue(idRaw),
			Error:   &rpcError{Code: -32600, Message: "Invalid Request: missing method"},
		}, true
	}

	return s.dispatch(req, decodeIDValue(idRaw)), true
}

func decodeIDValue(idRaw []byte) any {
	if len(idRaw) == 0 || bytes.Equal(idRaw, []byte("null")) {
		return nil
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(idRaw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	return v
}

func (s *Server) dispatch(req rpcRequest, reqID any) rpcResponse {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		proto := "2024-11-05"
		if p.ProtocolVersion == "2025-03-26" || p.ProtocolVersion == "2024-11-05" {
			proto = p.ProtocolVersion
		}
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Result: map[string]any{
				"protocolVersion": proto,
				"capabilities": map[string]any{
					"tools": map[string]any{
						"listChanged": false,
					},
				},
				"serverInfo": map[string]any{
					"name":    "symforge",
					"version": s.version,
				},
			},
		}

	case "ping":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Result:  map[string]any{},
		}

	case "tools/list":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Result: map[string]any{
				"tools": s.toolDefinitions(),
			},
		}

	case "resources/list":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Result:  map[string]any{"resources": []any{}},
		}

	case "prompts/list":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Result:  map[string]any{"prompts": []any{}},
		}

	case "tools/call":
		var callParams struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			return rpcResponse{
				JSONRPC: "2.0",
				ID:      reqID,
				Error:   &rpcError{Code: -32602, Message: "Invalid tools/call params: " + err.Error()},
			}
		}
		text, isErr, rpcErr := s.executeTool(callParams.Name, callParams.Arguments)
		if rpcErr != nil {
			return rpcResponse{
				JSONRPC: "2.0",
				ID:      reqID,
				Error:   rpcErr,
			}
		}
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Result: map[string]any{
				"content": []map[string]any{
					{
						"type": "text",
						"text": text,
					},
				},
				"isError": isErr,
			},
		}

	default:
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Error:   &rpcError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", req.Method)},
		}
	}
}

// Handler returns an http.Handler exposing /health, /mcp (Streamable HTTP), /sse, and /messages.
// Loopback Host and Origin checks protect local developers against browser DNS-rebinding attacks.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if !isSafeLocalRequest(r) {
			http.Error(w, "forbidden host or origin", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"server":  "symforge",
			"version": s.version,
		})
	})

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if !isSafeLocalRequest(r) {
			http.Error(w, "forbidden host or origin", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxFrameBytes))
		if err != nil {
			http.Error(w, "failed reading body", http.StatusBadRequest)
			return
		}
		respBytes, hasResp := s.handleRawJSON(body)
		if !hasResp {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(respBytes)
	})

	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		if !isSafeLocalRequest(r) {
			http.Error(w, "forbidden host or origin", http.StatusForbidden)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		sid := randomSessionID()
		ch := make(chan []byte, 32)
		s.sseMu.Lock()
		s.sessions[sid] = ch
		s.sseMu.Unlock()
		defer func() {
			s.sseMu.Lock()
			delete(s.sessions, sid)
			s.sseMu.Unlock()
		}()

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		fmt.Fprintf(w, "event: endpoint\ndata: /messages?sessionId=%s\n\n", sid)
		flusher.Flush()

		for {
			select {
			case <-r.Context().Done():
				return
			case msg := <-ch:
				fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(msg))
				flusher.Flush()
			}
		}
	})

	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		if !isSafeLocalRequest(r) {
			http.Error(w, "forbidden host or origin", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sid := r.URL.Query().Get("sessionId")
		s.sseMu.Lock()
		ch, exists := s.sessions[sid]
		s.sseMu.Unlock()
		if !exists {
			http.Error(w, "unknown sessionId", http.StatusNotFound)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxFrameBytes))
		if err != nil {
			http.Error(w, "failed reading body", http.StatusBadRequest)
			return
		}
		respBytes, hasResp := s.handleRawJSON(body)
		if hasResp {
			select {
			case ch <- respBytes:
			default:
			}
		}
		w.WriteHeader(http.StatusAccepted)
	})

	return mux
}

// ListenAndServeHTTP runs the MCP HTTP/SSE server until ctx is cancelled.
func (s *Server) ListenAndServeHTTP(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func isSafeLocalRequest(r *http.Request) bool {
	if r.Host != "" && !isLoopbackHostPort(r.Host) {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !isLoopbackHostPort(u.Host) {
			return false
		}
	}
	return true
}

func isLoopbackHostPort(hostPort string) bool {
	h := hostPort
	if splitHost, _, err := net.SplitHostPort(hostPort); err == nil {
		h = splitHost
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func randomSessionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
