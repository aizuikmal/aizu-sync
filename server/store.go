package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the metadata side: SQLite in WAL mode. All writes go through one
// mutex so a commit batch is a single serialized transaction.
type Store struct {
	db    *sql.DB
	blobs *BlobStore
	wmu   sync.Mutex
}

const schema = `
CREATE TABLE IF NOT EXISTS vault(
  id INTEGER PRIMARY KEY CHECK (id = 1),
  kdf_salt TEXT NOT NULL,
  kdf_iters INTEGER NOT NULL,
  key_check TEXT,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  token_sha256 TEXT NOT NULL UNIQUE,
  created INTEGER NOT NULL,
  revoked INTEGER,
  last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS files(
  file_id TEXT PRIMARY KEY,
  path_hmac TEXT NOT NULL,
  enc_path TEXT NOT NULL,
  version INTEGER NOT NULL,
  content_tag TEXT NOT NULL,
  blob_sha TEXT NOT NULL,
  size INTEGER NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  mtime INTEGER NOT NULL,
  device_id INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS files_live_path ON files(path_hmac) WHERE deleted = 0;
CREATE TABLE IF NOT EXISTS versions(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id TEXT NOT NULL,
  path_hmac TEXT NOT NULL,
  enc_path TEXT NOT NULL,
  content_tag TEXT NOT NULL,
  blob_sha TEXT NOT NULL,
  size INTEGER NOT NULL,
  deleted INTEGER NOT NULL,
  mtime INTEGER NOT NULL,
  device_id INTEGER NOT NULL,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS versions_file ON versions(file_id, seq);
CREATE INDEX IF NOT EXISTS versions_blob ON versions(blob_sha);
`

func OpenStore(dataDir string) (*Store, error) {
	dsn := "file:" + filepath.Join(dataDir, "obsync.db") +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	blobs, err := OpenBlobStore(dataDir)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, blobs: blobs}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// ---- vault ----

type VaultInfo struct {
	KDFSalt  string `json:"kdf_salt"`
	KDFIters int    `json:"kdf_iters"`
	KeyCheck string `json:"key_check"`
	Head     int64  `json:"head"`
}

func (s *Store) InitVault(iters int) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.db.Exec(`INSERT INTO vault(id, kdf_salt, kdf_iters, created) VALUES (1, ?, ?, ?)`,
		base64.StdEncoding.EncodeToString(salt), iters, time.Now().Unix())
	return err
}

func (s *Store) Vault() (*VaultInfo, error) {
	v := &VaultInfo{}
	var kc sql.NullString
	err := s.db.QueryRow(`SELECT kdf_salt, kdf_iters, key_check FROM vault WHERE id = 1`).Scan(&v.KDFSalt, &v.KDFIters, &kc)
	if err != nil {
		return nil, err
	}
	v.KeyCheck = kc.String
	v.Head, err = s.Head()
	return v, err
}

var ErrKeyCheckSet = errors.New("key_check already set")

// SetKeyCheck stores the first device's encrypted known value. It is set once:
// a device with a different passphrase must fail to decrypt it, not replace it.
func (s *Store) SetKeyCheck(kc string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	res, err := s.db.Exec(`UPDATE vault SET key_check = ? WHERE id = 1 AND key_check IS NULL`, kc)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrKeyCheckSet
	}
	return nil
}

func (s *Store) Head() (int64, error) {
	var h sql.NullInt64
	err := s.db.QueryRow(`SELECT MAX(seq) FROM versions`).Scan(&h)
	return h.Int64, err
}

// ---- devices ----

type Device struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Created  int64  `json:"created"`
	Revoked  int64  `json:"revoked,omitempty"`
	LastSeen int64  `json:"last_seen,omitempty"`
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// MaxDevices is the default for how many devices may hold an active token at once.
// $OBSYNC_MAX_DEVICES changes the default; `device add -max N` overrides both.
const MaxDevices = 10

func maxDevices() int {
	if n, err := strconv.Atoi(os.Getenv("OBSYNC_MAX_DEVICES")); err == nil && n > 0 {
		return n
	}
	return MaxDevices
}

var ErrDeviceLimit = errors.New("device limit reached; revoke a device first")

// AddDevice returns the plaintext token; only its sha256 is stored. It refuses
// once max devices are active, so a new device has to replace a revoked one.
func (s *Store) AddDevice(name string, max int) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := "obs_" + base64.RawURLEncoding.EncodeToString(raw)
	s.wmu.Lock()
	defer s.wmu.Unlock()
	var active int
	if err := s.db.QueryRow(`SELECT count(*) FROM devices WHERE revoked IS NULL`).Scan(&active); err != nil {
		return "", err
	}
	if active >= max {
		return "", ErrDeviceLimit
	}
	_, err := s.db.Exec(`INSERT INTO devices(name, token_sha256, created) VALUES (?, ?, ?)`, name, hashToken(tok), time.Now().Unix())
	return tok, err
}

func (s *Store) RevokeDevice(name string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	res, err := s.db.Exec(`UPDATE devices SET revoked = ? WHERE name = ? AND revoked IS NULL`, time.Now().Unix(), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no active device named %q", name)
	}
	return nil
}

func (s *Store) Devices() ([]Device, error) {
	rows, err := s.db.Query(`SELECT id, name, created, COALESCE(revoked, 0), COALESCE(last_seen, 0) FROM devices ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Name, &d.Created, &d.Revoked, &d.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Authenticate maps a bearer token to an active device.
func (s *Store) Authenticate(tok string) (*Device, error) {
	d := &Device{}
	var last sql.NullInt64
	err := s.db.QueryRow(`SELECT id, name, last_seen FROM devices WHERE token_sha256 = ? AND revoked IS NULL`, hashToken(tok)).
		Scan(&d.ID, &d.Name, &last)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if now-last.Int64 > 60 { // don't turn every read into a write
		s.wmu.Lock()
		s.db.Exec(`UPDATE devices SET last_seen = ? WHERE id = ?`, now, d.ID)
		s.wmu.Unlock()
	}
	return d, nil
}

// ---- files ----

type FileMeta struct {
	FileID     string `json:"file_id"`
	Version    int64  `json:"version"`
	PathHMAC   string `json:"path_hmac"`
	EncPath    string `json:"enc_path"`
	ContentTag string `json:"content_tag"`
	BlobSHA    string `json:"blob_sha"`
	Size       int64  `json:"size"`
	Deleted    bool   `json:"deleted"`
	Mtime      int64  `json:"mtime"`
	DeviceID   int64  `json:"device_id"`
	TS         int64  `json:"ts,omitempty"`
}

const fileCols = `file_id, version, path_hmac, enc_path, content_tag, blob_sha, size, deleted, mtime, device_id`
const versionCols = `file_id, seq, path_hmac, enc_path, content_tag, blob_sha, size, deleted, mtime, device_id, ts`

type scanner interface{ Scan(...any) error }

func scanFile(r scanner, withTS bool) (*FileMeta, error) {
	f := &FileMeta{}
	dst := []any{&f.FileID, &f.Version, &f.PathHMAC, &f.EncPath, &f.ContentTag, &f.BlobSHA, &f.Size, &f.Deleted, &f.Mtime, &f.DeviceID}
	if withTS {
		dst = append(dst, &f.TS)
	}
	return f, r.Scan(dst...)
}

func collect(rows *sql.Rows, withTS bool) ([]*FileMeta, error) {
	defer rows.Close()
	out := []*FileMeta{}
	for rows.Next() {
		f, err := scanFile(rows, withTS)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) State(includeDeleted bool) ([]*FileMeta, error) {
	q := `SELECT ` + fileCols + ` FROM files`
	if !includeDeleted {
		q += ` WHERE deleted = 0`
	}
	rows, err := s.db.Query(q + ` ORDER BY version`)
	if err != nil {
		return nil, err
	}
	return collect(rows, false)
}

func (s *Store) Changes(since int64, limit int) ([]*FileMeta, error) {
	rows, err := s.db.Query(`SELECT `+versionCols+` FROM versions WHERE seq > ? ORDER BY seq LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, true)
}

func (s *Store) History(fileID string) ([]*FileMeta, error) {
	rows, err := s.db.Query(`SELECT `+versionCols+` FROM versions WHERE file_id = ? ORDER BY seq`, fileID)
	if err != nil {
		return nil, err
	}
	return collect(rows, true)
}

// ---- commit ----

type CommitItem struct {
	FileID      string `json:"file_id"`
	BaseVersion int64  `json:"base_version"` // 0 = create
	PathHMAC    string `json:"path_hmac"`
	EncPath     string `json:"enc_path"`
	ContentTag  string `json:"content_tag"`
	BlobSHA     string `json:"blob_sha"`
	Size        int64  `json:"size"`
	Deleted     bool   `json:"deleted"`
	Mtime       int64  `json:"mtime"`
	Blob        string `json:"blob,omitempty"` // optional inline ciphertext, base64
}

type CommitResult struct {
	FileID  string    `json:"file_id"`
	OK      bool      `json:"ok"`
	Version int64     `json:"version,omitempty"`
	Error   string    `json:"error,omitempty"` // conflict | path_exists | missing_blob | bad_request
	Detail  string    `json:"detail,omitempty"`
	Current *FileMeta `json:"current,omitempty"`
}

// Commit applies a batch in one transaction. Items are independent: one
// item's conflict does not stop the others. Every accepted item appends a
// versions row; nothing is ever overwritten or removed.
func (s *Store) Commit(dev *Device, items []CommitItem) ([]CommitResult, int64, error) {
	results := make([]CommitResult, len(items))
	// Blob bytes go to disk (fsynced) before any metadata row can point at them.
	for i := range items {
		it := &items[i]
		results[i].FileID = it.FileID
		if msg := validate(it); msg != "" {
			results[i].Error, results[i].Detail = "bad_request", msg
			continue
		}
		if it.Blob != "" {
			data, err := base64.StdEncoding.DecodeString(it.Blob)
			if err != nil {
				results[i].Error, results[i].Detail = "bad_request", "blob is not base64"
				continue
			}
			if err := s.blobs.Put(it.BlobSHA, data); err != nil {
				results[i].Error, results[i].Detail = "bad_request", err.Error()
				continue
			}
			it.Blob = ""
		}
	}

	s.wmu.Lock()
	defer s.wmu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	var head int64
	for i := range items {
		if results[i].Error != "" {
			continue
		}
		r, err := commitOne(tx, s.blobs, dev, &items[i], now)
		if err != nil {
			return nil, 0, err
		}
		results[i] = r
		if r.OK && r.Version > head {
			head = r.Version
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return results, head, nil
}

func commitOne(tx *sql.Tx, blobs *BlobStore, dev *Device, it *CommitItem, now int64) (CommitResult, error) {
	res := CommitResult{FileID: it.FileID}
	cur, err := scanFile(tx.QueryRow(`SELECT `+fileCols+` FROM files WHERE file_id = ?`, it.FileID), false)
	if errors.Is(err, sql.ErrNoRows) {
		cur = nil
	} else if err != nil {
		return res, err
	}
	switch {
	case cur == nil && it.BaseVersion != 0:
		res.Error, res.Detail = "conflict", "unknown file_id"
		return res, nil
	case cur != nil && it.BaseVersion != cur.Version:
		res.Error, res.Current = "conflict", cur
		return res, nil
	case cur == nil && it.Deleted:
		res.Error, res.Detail = "bad_request", "cannot create a tombstone"
		return res, nil
	}
	if !it.Deleted {
		other, err := scanFile(tx.QueryRow(`SELECT `+fileCols+` FROM files WHERE path_hmac = ? AND deleted = 0 AND file_id <> ?`, it.PathHMAC, it.FileID), false)
		if err == nil {
			res.Error, res.Current = "path_exists", other
			return res, nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return res, err
		}
		if !blobs.Has(it.BlobSHA) {
			res.Error = "missing_blob"
			return res, nil
		}
	}
	r, err := tx.Exec(`INSERT INTO versions(file_id, path_hmac, enc_path, content_tag, blob_sha, size, deleted, mtime, device_id, ts)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		it.FileID, it.PathHMAC, it.EncPath, it.ContentTag, it.BlobSHA, it.Size, it.Deleted, it.Mtime, dev.ID, now)
	if err != nil {
		return res, err
	}
	seq, _ := r.LastInsertId()
	_, err = tx.Exec(`INSERT INTO files(`+fileCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(file_id) DO UPDATE SET version=excluded.version, path_hmac=excluded.path_hmac, enc_path=excluded.enc_path,
		content_tag=excluded.content_tag, blob_sha=excluded.blob_sha, size=excluded.size, deleted=excluded.deleted,
		mtime=excluded.mtime, device_id=excluded.device_id`,
		it.FileID, seq, it.PathHMAC, it.EncPath, it.ContentTag, it.BlobSHA, it.Size, it.Deleted, it.Mtime, dev.ID)
	if err != nil {
		return res, err
	}
	res.OK, res.Version = true, seq
	return res, nil
}

func validate(it *CommitItem) string {
	switch {
	case !reFileID.MatchString(it.FileID):
		return "file_id"
	case it.BaseVersion < 0:
		return "base_version"
	case !reHex64.MatchString(it.PathHMAC):
		return "path_hmac"
	case it.EncPath == "" || len(it.EncPath) > 8192:
		return "enc_path"
	case it.Size < 0:
		return "size"
	}
	if it.Deleted {
		if it.Blob != "" {
			return "tombstone with blob"
		}
		return ""
	}
	if !reHex64.MatchString(it.ContentTag) {
		return "content_tag"
	}
	if !reHex64.MatchString(it.BlobSHA) {
		return "blob_sha"
	}
	return ""
}

// Snapshot writes a consistent copy of the database (for backups).
func (s *Store) Snapshot(out string) error {
	_, err := s.db.Exec(`VACUUM INTO ?`, out)
	return err
}

// ReferencedBlobs returns every blob sha that any version points at.
func (s *Store) ReferencedBlobs() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT DISTINCT blob_sha FROM versions WHERE blob_sha <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			return nil, err
		}
		out[sha] = true
	}
	return out, rows.Err()
}

func (s *Store) IntegrityCheck() (string, error) {
	var r string
	err := s.db.QueryRow(`PRAGMA integrity_check`).Scan(&r)
	return r, err
}
