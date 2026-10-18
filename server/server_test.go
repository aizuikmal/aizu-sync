package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type env struct {
	t   *testing.T
	st  *Store
	srv *httptest.Server
	tok string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitVault(1000); err != nil {
		t.Fatal(err)
	}
	tok, err := st.AddDevice("mac-a", MaxDevices)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(st).Routes())
	t.Cleanup(func() { srv.Close(); st.Close() })
	return &env{t: t, st: st, srv: srv, tok: tok}
}

func (e *env) do(method, path, tok string, body any, out any) int {
	e.t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func hex64(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func uuid4() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// item builds a commit with inline ciphertext.
func item(id string, base int64, path, content string) CommitItem {
	blob := []byte("ct:" + content)
	sum := sha256.Sum256(blob)
	return CommitItem{FileID: id, BaseVersion: base, PathHMAC: hex64("p:" + path), EncPath: "enc:" + path,
		ContentTag: hex64("c:" + content), BlobSHA: hex.EncodeToString(sum[:]), Size: int64(len(content)),
		Mtime: 1, Blob: base64.StdEncoding.EncodeToString(blob)}
}

type commitResp struct {
	Results []CommitResult `json:"results"`
	Head    int64          `json:"head"`
}

func (e *env) commit(tok string, items ...CommitItem) commitResp {
	e.t.Helper()
	var out commitResp
	if code := e.do("POST", "/v1/commit", tok, map[string]any{"items": items}, &out); code != 200 {
		e.t.Fatalf("commit: HTTP %d", code)
	}
	return out
}

func TestAuth(t *testing.T) {
	e := newEnv(t)
	if c := e.do("GET", "/v1/state", "", nil, nil); c != 401 {
		t.Fatalf("no token: %d", c)
	}
	if c := e.do("GET", "/v1/state", "obs_wrong", nil, nil); c != 401 {
		t.Fatalf("bad token: %d", c)
	}
	if c := e.do("GET", "/v1/state", e.tok, nil, nil); c != 200 {
		t.Fatalf("good token: %d", c)
	}
	if err := e.st.RevokeDevice("mac-a"); err != nil {
		t.Fatal(err)
	}
	if c := e.do("GET", "/v1/state", e.tok, nil, nil); c != 401 {
		t.Fatalf("revoked token: %d", c)
	}
	if c := e.do("GET", "/healthz", "", nil, nil); c != 200 {
		t.Fatalf("healthz: %d", c)
	}
}

func TestCreateEditCAS(t *testing.T) {
	e := newEnv(t)
	id := uuid4()
	r := e.commit(e.tok, item(id, 0, "a.md", "one"))
	if !r.Results[0].OK {
		t.Fatalf("create: %+v", r.Results[0])
	}
	v1 := r.Results[0].Version

	// create again with base 0 -> conflict
	r = e.commit(e.tok, item(id, 0, "a.md", "dup"))
	if r.Results[0].Error != "conflict" || r.Results[0].Current.Version != v1 {
		t.Fatalf("re-create: %+v", r.Results[0])
	}
	// edit on the right base
	r = e.commit(e.tok, item(id, v1, "a.md", "two"))
	if !r.Results[0].OK {
		t.Fatalf("edit: %+v", r.Results[0])
	}
	v2 := r.Results[0].Version
	// stale base -> conflict carrying current
	r = e.commit(e.tok, item(id, v1, "a.md", "stale"))
	if r.Results[0].Error != "conflict" || r.Results[0].Current.Version != v2 || r.Results[0].Current.ContentTag != hex64("c:two") {
		t.Fatalf("stale: %+v", r.Results[0])
	}
	// unknown file with nonzero base
	r = e.commit(e.tok, item(uuid4(), 5, "b.md", "x"))
	if r.Results[0].Error != "conflict" {
		t.Fatalf("unknown: %+v", r.Results[0])
	}
	var h struct{ Versions []FileMeta }
	e.do("GET", "/v1/history/"+id, e.tok, nil, &h)
	if len(h.Versions) != 2 {
		t.Fatalf("history len %d", len(h.Versions))
	}
}

// N writers race on one base: exactly one wins, the rest get 409 with the winner.
func TestConcurrentCAS(t *testing.T) {
	e := newEnv(t)
	id := uuid4()
	base := e.commit(e.tok, item(id, 0, "race.md", "base")).Results[0].Version
	const n = 16
	var wg sync.WaitGroup
	results := make([]CommitResult, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = e.commit(e.tok, item(id, base, "race.md", fmt.Sprint("w", i))).Results[0]
		}(i)
	}
	wg.Wait()
	wins := 0
	var winner int64
	for _, r := range results {
		if r.OK {
			wins++
			winner = r.Version
		}
	}
	if wins != 1 {
		t.Fatalf("wins = %d", wins)
	}
	for _, r := range results {
		if !r.OK && (r.Error != "conflict" || r.Current.Version != winner) {
			t.Fatalf("loser: %+v", r)
		}
	}
}

func TestPathUniquenessRenameDelete(t *testing.T) {
	e := newEnv(t)
	a, b := uuid4(), uuid4()
	va := e.commit(e.tok, item(a, 0, "x.md", "A")).Results[0].Version
	// second file on the same live path -> path_exists pointing at a
	r := e.commit(e.tok, item(b, 0, "x.md", "B")).Results[0]
	if r.Error != "path_exists" || r.Current.FileID != a {
		t.Fatalf("dup path: %+v", r)
	}
	// rename a -> y.md, keeps file_id
	va = e.commit(e.tok, item(a, va, "y.md", "A")).Results[0].Version
	// now b can take x.md
	if r := e.commit(e.tok, item(b, 0, "x.md", "B")).Results[0]; !r.OK {
		t.Fatalf("after rename: %+v", r)
	}
	// delete a (tombstone keeps its path), then a new file may use y.md
	del := CommitItem{FileID: a, BaseVersion: va, PathHMAC: hex64("p:y.md"), EncPath: "enc:y.md", Deleted: true, Mtime: 2}
	r = e.commit(e.tok, del).Results[0]
	if !r.OK {
		t.Fatalf("delete: %+v", r)
	}
	vdel := r.Version
	c := uuid4()
	if r := e.commit(e.tok, item(c, 0, "y.md", "C")).Results[0]; !r.OK {
		t.Fatalf("reuse path: %+v", r)
	}
	// resurrecting a onto y.md now collides with c
	if r := e.commit(e.tok, item(a, vdel, "y.md", "A2")).Results[0]; r.Error != "path_exists" {
		t.Fatalf("resurrect collide: %+v", r)
	}
	// resurrect a under another name works
	if r := e.commit(e.tok, item(a, vdel, "y (restored).md", "A2")).Results[0]; !r.OK {
		t.Fatalf("resurrect: %+v", r)
	}
	var live, all struct{ Files []FileMeta }
	e.do("GET", "/v1/state", e.tok, nil, &live)
	e.do("GET", "/v1/state?deleted=1", e.tok, nil, &all)
	if len(live.Files) != 3 || len(all.Files) != 3 {
		t.Fatalf("state live=%d all=%d", len(live.Files), len(all.Files))
	}
}

func TestBlobsAndMissingBlob(t *testing.T) {
	e := newEnv(t)
	it := item(uuid4(), 0, "n.md", "hello")
	it.Blob = "" // reference a blob that was never uploaded
	if r := e.commit(e.tok, it).Results[0]; r.Error != "missing_blob" {
		t.Fatalf("missing blob: %+v", r)
	}
	data := []byte("ct:hello")
	if c := e.do("PUT", "/v1/blob/"+it.BlobSHA, e.tok, []byte("tampered"), nil); c != 400 {
		t.Fatalf("sha mismatch accepted: %d", c)
	}
	if c := e.do("PUT", "/v1/blob/"+it.BlobSHA, e.tok, data, nil); c != 200 {
		t.Fatalf("put blob: %d", c)
	}
	if r := e.commit(e.tok, it).Results[0]; !r.OK {
		t.Fatalf("commit after upload: %+v", r)
	}
	var out struct {
		Blobs   map[string]string
		Missing []string
	}
	e.do("POST", "/v1/blobs", e.tok, map[string]any{"shas": []string{it.BlobSHA, hex64("nope")}}, &out)
	got, _ := base64.StdEncoding.DecodeString(out.Blobs[it.BlobSHA])
	if string(got) != string(data) || len(out.Missing) != 1 {
		t.Fatalf("batch get: %+v", out)
	}
	if c := e.do("GET", "/v1/blob/../../obsync.db", e.tok, nil, nil); c == 200 {
		t.Fatal("path traversal")
	}
}

func TestBadRequestsAndBatchIndependence(t *testing.T) {
	e := newEnv(t)
	good := item(uuid4(), 0, "ok.md", "ok")
	bad := item("../../etc", 0, "bad.md", "bad")
	tomb := CommitItem{FileID: uuid4(), PathHMAC: hex64("p:t"), EncPath: "e", Deleted: true}
	r := e.commit(e.tok, bad, good, tomb)
	if r.Results[0].Error != "bad_request" || !r.Results[1].OK || r.Results[2].Error != "bad_request" {
		t.Fatalf("batch: %+v", r.Results)
	}
	if r.Head != r.Results[1].Version {
		t.Fatalf("head %d vs %d", r.Head, r.Results[1].Version)
	}
}

func TestChangesFeed(t *testing.T) {
	e := newEnv(t)
	var items []CommitItem
	for i := 0; i < 5; i++ {
		items = append(items, item(uuid4(), 0, fmt.Sprint("f", i, ".md"), fmt.Sprint(i)))
	}
	e.commit(e.tok, items...)
	var ch struct {
		Changes []FileMeta
		More    bool
	}
	e.do("GET", "/v1/changes?since=0&limit=3", e.tok, nil, &ch)
	if len(ch.Changes) != 3 || !ch.More {
		t.Fatalf("page1 %d more=%v", len(ch.Changes), ch.More)
	}
	last := ch.Changes[2].Version
	e.do("GET", fmt.Sprintf("/v1/changes?since=%d", last), e.tok, nil, &ch)
	if len(ch.Changes) != 2 || ch.More || ch.Changes[0].Version <= last {
		t.Fatalf("page2 %+v", ch)
	}
}

func TestKeyCheckAdminOnly(t *testing.T) {
	e := newEnv(t)
	// no device can set (or overwrite) the passphrase check over the API
	if c := e.do("PUT", "/v1/vault/key_check", e.tok, map[string]string{"key_check": "evil"}, nil); c == 200 {
		t.Fatalf("device set key_check: %d", c)
	}
	if err := e.st.SetKeyCheck("first"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetKeyCheck("second"); !errors.Is(err, ErrKeyCheckSet) {
		t.Fatalf("overwrite: %v", err)
	}
	var v VaultInfo
	e.do("GET", "/v1/vault", e.tok, nil, &v)
	if v.KeyCheck != "first" || v.KDFIters != 1000 || v.KDFSalt == "" {
		t.Fatalf("vault %+v", v)
	}
}

func TestDeviceLimit(t *testing.T) {
	e := newEnv(t) // mac-a is device 1; limit 3
	for _, n := range []string{"mac-b", "iphone"} {
		if _, err := e.st.AddDevice(n, 3); err != nil {
			t.Fatal(n, err)
		}
	}
	if _, err := e.st.AddDevice("intruder", 3); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("4th device: %v", err)
	}
	if err := e.st.RevokeDevice("mac-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.AddDevice("mac-b2", 3); err != nil {
		t.Fatalf("replacement after revoke: %v", err)
	}
}

func TestWebSocketNotify(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/v1/ws"

	bad, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	wsjson.Write(ctx, bad, map[string]string{"token": "nope"})
	var m wsMsg
	if err := wsjson.Read(ctx, bad, &m); websocket.CloseStatus(err) != 4401 {
		t.Fatalf("bad token ws: %v", err)
	}

	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	wsjson.Write(ctx, c, map[string]string{"token": e.tok})
	if err := wsjson.Read(ctx, c, &m); err != nil || m.Type != "hello" {
		t.Fatalf("hello: %+v %v", m, err)
	}
	r := e.commit(e.tok, item(uuid4(), 0, "w.md", "w"))
	if err := wsjson.Read(ctx, c, &m); err != nil || m.Type != "head" || m.Head != r.Head {
		t.Fatalf("notify: %+v %v", m, err)
	}
}

func TestVerifyAndGC(t *testing.T) {
	e := newEnv(t)
	it := item(uuid4(), 0, "v.md", "v")
	e.commit(e.tok, it)
	orphan := []byte("orphan")
	sum := sha256.Sum256(orphan)
	e.st.blobs.Put(hex.EncodeToString(sum[:]), orphan)
	if !verify(e.st) {
		t.Fatal("verify should pass")
	}
	ref, _ := e.st.ReferencedBlobs()
	if o, _ := e.st.blobs.Orphans(ref, time.Hour); len(o) != 0 {
		t.Fatal("fresh orphan must be protected by minAge")
	}
	if o, _ := e.st.blobs.Orphans(ref, 0); len(o) != 1 {
		t.Fatalf("orphans %v", o)
	}
	// corrupt the referenced blob -> verify fails
	os.WriteFile(e.st.blobs.path(it.BlobSHA), []byte("rot"), 0o600)
	if verify(e.st) {
		t.Fatal("verify should fail on corruption")
	}
	if err := e.st.Snapshot(t.TempDir() + "/snap.db"); err != nil {
		t.Fatal(err)
	}
}

// Cross-language vectors: the plugin (WebCrypto) and obsyncd set-passphrase
// must derive the same key. TSVEC was made by plugin/src/core/crypto.ts;
// plugin/test/crypto.test.ts checks the Go-made one the other way round.
const (
	vecPass = "correct-horse-battery-staple"
	vecSalt = "AAECAwQFBgcICQoLDA0ODw=="
	vecTS   = "aFSLtbpe4MR4h+p8t+YfcLNfUNAPr8SqUQIH3bpPWSlvqr++o1Pr6qz+y+1JBYejdm0="
)

func TestKeyCheckMatchesPlugin(t *testing.T) {
	if !verifyKeyCheck(vecPass, vecSalt, 1000, vecTS) {
		t.Fatal("Go rejects the plugin's key_check")
	}
	if verifyKeyCheck(vecPass+"x", vecSalt, 1000, vecTS) {
		t.Fatal("wrong passphrase accepted")
	}
	kc, err := makeKeyCheck(vecPass, vecSalt, 1000)
	if err != nil || !verifyKeyCheck(vecPass, vecSalt, 1000, kc) {
		t.Fatal("round trip", err)
	}
	if _, err := makeKeyCheck("short", vecSalt, 1000); err == nil {
		t.Fatal("short passphrase accepted")
	}
	if p := generatePassphrase(); len(p) != 29 || checkPassphrase(p) != nil {
		t.Fatalf("generated %q", p)
	}
}

func TestMaxDevicesEnv(t *testing.T) {
	t.Setenv("OBSYNC_MAX_DEVICES", "")
	if maxDevices() != MaxDevices {
		t.Fatal("default")
	}
	t.Setenv("OBSYNC_MAX_DEVICES", "3")
	if maxDevices() != 3 {
		t.Fatal("env not used")
	}
	t.Setenv("OBSYNC_MAX_DEVICES", "zero")
	if maxDevices() != MaxDevices {
		t.Fatal("garbage should fall back")
	}
}
