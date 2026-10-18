package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

const (
	maxBody      = 64 << 20 // one request
	maxBatchBlob = 32 << 20 // total bytes returned by POST /v1/blobs
	maxChanges   = 2000
)

type Server struct {
	st  *Store
	hub *Hub
}

func NewServer(st *Store) *Server { return &Server{st: st, hub: NewHub()} }

func (s *Server) Routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	m.HandleFunc("GET /v1/vault", s.auth(s.getVault))
	m.HandleFunc("GET /v1/state", s.auth(s.getState))
	m.HandleFunc("GET /v1/changes", s.auth(s.getChanges))
	m.HandleFunc("GET /v1/history/{id}", s.auth(s.getHistory))
	m.HandleFunc("GET /v1/blob/{sha}", s.auth(s.getBlob))
	m.HandleFunc("PUT /v1/blob/{sha}", s.auth(s.putBlob))
	m.HandleFunc("POST /v1/blobs", s.auth(s.postBlobs))
	m.HandleFunc("POST /v1/commit", s.auth(s.postCommit))
	m.HandleFunc("GET /v1/ws", s.ws)
	return cors(m)
}

// cors: auth is a bearer token, never a cookie, so a wildcard origin is safe.
func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

func deviceOf(r *http.Request) *Device { return r.Context().Value(ctxKey{}).(*Device) }

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || tok == "" {
			httpErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		dev, err := s.st.Authenticate(tok)
		if err != nil {
			httpErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, dev)))
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func serverErr(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("%s %s: %v", r.Method, r.URL.Path, err)
	httpErr(w, http.StatusInternalServerError, "internal")
}

func (s *Server) getVault(w http.ResponseWriter, r *http.Request) {
	v, err := s.st.Vault()
	if err != nil {
		serverErr(w, r, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) getState(w http.ResponseWriter, r *http.Request) {
	head, err := s.st.Head() // read head first: changes after it will be re-sent, never missed
	if err != nil {
		serverErr(w, r, err)
		return
	}
	files, err := s.st.State(r.URL.Query().Get("deleted") == "1")
	if err != nil {
		serverErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"head": head, "files": files})
}

func (s *Server) getChanges(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > maxChanges {
		limit = maxChanges
	}
	ch, err := s.st.Changes(since, limit+1)
	if err != nil {
		serverErr(w, r, err)
		return
	}
	more := len(ch) > limit
	if more {
		ch = ch[:limit]
	}
	writeJSON(w, 200, map[string]any{"changes": ch, "more": more})
}

func (s *Server) getHistory(w http.ResponseWriter, r *http.Request) {
	h, err := s.st.History(r.PathValue("id"))
	if err != nil {
		serverErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"versions": h})
}

func (s *Server) getBlob(w http.ResponseWriter, r *http.Request) {
	data, err := s.st.blobs.Get(r.PathValue("sha"))
	if err != nil {
		httpErr(w, 404, "not_found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (s *Server) putBlob(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		httpErr(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}
	if err := s.st.blobs.Put(r.PathValue("sha"), data); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) postBlobs(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SHAs []string `json:"shas"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpErr(w, 400, "bad_request")
		return
	}
	out := map[string]string{}
	missing := []string{}
	rest := []string{} // over the size budget: client fetches these in the next call
	total := 0
	for _, sha := range body.SHAs {
		if total >= maxBatchBlob {
			rest = append(rest, sha)
			continue
		}
		data, err := s.st.blobs.Get(sha)
		if err != nil {
			missing = append(missing, sha)
			continue
		}
		total += len(data)
		out[sha] = base64.StdEncoding.EncodeToString(data)
	}
	writeJSON(w, 200, map[string]any{"blobs": out, "missing": missing, "rest": rest})
}

func (s *Server) postCommit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Items []CommitItem `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Items) == 0 || len(body.Items) > 500 {
		httpErr(w, 400, "bad_request")
		return
	}
	dev := deviceOf(r)
	results, head, err := s.st.Commit(dev, body.Items)
	if err != nil {
		serverErr(w, r, err)
		return
	}
	if head > 0 {
		s.hub.Broadcast(head, dev.ID)
	} else if head, err = s.st.Head(); err != nil {
		serverErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"results": results, "head": head})
}

// ---- websocket: commit notifications only, never content ----

type Hub struct {
	mu    sync.Mutex
	conns map[chan wsMsg]struct{}
}

type wsMsg struct {
	Type   string `json:"type"`
	Head   int64  `json:"head"`
	Device int64  `json:"device,omitempty"`
}

func NewHub() *Hub { return &Hub{conns: map[chan wsMsg]struct{}{}} }

func (h *Hub) Broadcast(head, device int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.conns {
		select {
		case c <- wsMsg{Type: "head", Head: head, Device: device}:
		default: // slow client: it will catch up from /changes on the next message
		}
	}
}

func (h *Hub) add(c chan wsMsg)    { h.mu.Lock(); h.conns[c] = struct{}{}; h.mu.Unlock() }
func (h *Hub) remove(c chan wsMsg) { h.mu.Lock(); delete(h.conns, c); h.mu.Unlock() }

// ws authenticates with the first message ({"token": "..."}) because browser
// WebSockets cannot send an Authorization header.
func (s *Server) ws(w http.ResponseWriter, r *http.Request) {
	// InsecureSkipVerify here skips the Origin check only (TLS is terminated by the reverse proxy).
	// Obsidian connects from app://obsidian.md or capacitor://localhost; auth is the token.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(4096)

	actx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	var hello struct {
		Token string `json:"token"`
	}
	err = wsjson.Read(actx, c, &hello)
	cancel()
	if err != nil {
		return
	}
	if _, err := s.st.Authenticate(hello.Token); err != nil {
		c.Close(4401, "unauthorized")
		return
	}
	head, err := s.st.Head()
	if err != nil {
		return
	}
	ctx := c.CloseRead(r.Context())
	ch := make(chan wsMsg, 16)
	s.hub.add(ch)
	defer s.hub.remove(ch)

	if err := wsjson.Write(ctx, c, wsMsg{Type: "hello", Head: head}); err != nil {
		return
	}
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-ch:
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := wsjson.Write(wctx, c, m)
			cancel()
			if err != nil {
				return
			}
		case <-ping.C:
			// a revoked device loses its notification feed within one tick
			if _, err := s.st.Authenticate(hello.Token); err != nil {
				c.Close(4401, "unauthorized")
				return
			}
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
