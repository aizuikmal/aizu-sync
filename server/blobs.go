package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var (
	reHex64  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reFileID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// BlobStore keeps ciphertext content-addressed by sha256 under blobs/ab/cd/<sha>.
// Writes are tmp + fsync + rename + dir fsync, so a blob is either whole or absent.
type BlobStore struct{ root, tmp string }

func OpenBlobStore(dataDir string) (*BlobStore, error) {
	b := &BlobStore{root: filepath.Join(dataDir, "blobs"), tmp: filepath.Join(dataDir, "tmp")}
	for _, d := range []string{b.root, b.tmp} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func (b *BlobStore) path(sha string) string {
	return filepath.Join(b.root, sha[:2], sha[2:4], sha)
}

func (b *BlobStore) Has(sha string) bool {
	if !reHex64.MatchString(sha) {
		return false
	}
	_, err := os.Stat(b.path(sha))
	return err == nil
}

func (b *BlobStore) Get(sha string) ([]byte, error) {
	if !reHex64.MatchString(sha) {
		return nil, fmt.Errorf("bad sha")
	}
	return os.ReadFile(b.path(sha))
}

func (b *BlobStore) Put(sha string, data []byte) error {
	if !reHex64.MatchString(sha) {
		return fmt.Errorf("bad sha")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != sha {
		return fmt.Errorf("sha mismatch")
	}
	if b.Has(sha) {
		return nil
	}
	return writeAtomic(b.tmp, b.path(sha), data)
}

// Walk calls fn for every stored blob.
func (b *BlobStore) Walk(fn func(sha, path string, info fs.FileInfo) error) error {
	return filepath.WalkDir(b.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return fn(d.Name(), p, info)
	})
}

// Orphans lists blobs no version references, older than minAge (so an upload
// whose commit is still in flight is never touched).
func (b *BlobStore) Orphans(referenced map[string]bool, minAge time.Duration) ([]string, error) {
	var out []string
	cutoff := time.Now().Add(-minAge)
	err := b.Walk(func(sha, p string, info fs.FileInfo) error {
		if !referenced[sha] && info.ModTime().Before(cutoff) {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

// writeAtomic: tmp + fsync + rename + dir fsync, so dst is either whole or absent.
func writeAtomic(tmpDir, dst string, data []byte) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(tmpDir, "up-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
