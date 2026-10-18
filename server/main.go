// obsyncd — aizu-sync server. Stores end-to-end encrypted blobs and their
// version history; it never sees plaintext and never merges.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

const usage = `obsyncd — aizu-sync server

  obsyncd [-data DIR] serve [-listen 127.0.0.1:8787]
  obsyncd [-data DIR] init [-iters N]       create the vault (salt, KDF params)
  obsyncd [-data DIR] set-passphrase [-generate]  set the vault passphrase (once; never stored)
  obsyncd [-data DIR] set-key-check         stdin: a key_check made elsewhere (advanced)
  obsyncd [-data DIR] device add [-max N] NAME   prints the device token once
  obsyncd [-data DIR] device limit [N]      show / store the active-device limit (0 = remove)
  obsyncd [-data DIR] device list
  obsyncd [-data DIR] device revoke NAME
  obsyncd [-data DIR] verify                integrity_check + re-hash every blob
  obsyncd [-data DIR] snapshot OUT.db       consistent DB copy for backups
  obsyncd [-data DIR] gc [-apply]           list (or remove) unreferenced blobs > 1h old
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	def := os.Getenv("OBSYNC_DATA")
	if def == "" {
		def = "/var/lib/obsync"
	}
	data := flag.String("data", def, "data directory (default $OBSYNC_DATA, else /var/lib/obsync)")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := os.MkdirAll(*data, 0o700); err != nil {
		log.Fatal(err)
	}
	st, err := OpenStore(*data)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	switch args[0] {
	case "serve":
		sf := flag.NewFlagSet("serve", flag.ExitOnError)
		listen := sf.String("listen", "127.0.0.1:8787", "listen address")
		sf.Parse(args[1:])
		if _, err := st.Vault(); err != nil {
			log.Fatal("vault not initialised; run: obsyncd init")
		}
		serve(st, *listen)
	case "init":
		sf := flag.NewFlagSet("init", flag.ExitOnError)
		iters := sf.Int("iters", 600000, "PBKDF2 iterations (lower only for tests)")
		sf.Parse(args[1:])
		if err := st.InitVault(*iters); err != nil {
			log.Fatal(err)
		}
		fmt.Println("vault created")
	case "set-key-check":
		kc, err := io.ReadAll(io.LimitReader(os.Stdin, 2048))
		if err != nil {
			log.Fatal(err)
		}
		k := strings.TrimSpace(string(kc))
		if k == "" || len(k) > 1024 {
			log.Fatal("expected the key_check (base64) on stdin")
		}
		if err := st.SetKeyCheck(k); err != nil {
			log.Fatal(err)
		}
		fmt.Println("key_check set")
	case "set-passphrase":
		sf := flag.NewFlagSet("set-passphrase", flag.ExitOnError)
		gen := sf.Bool("generate", false, "generate a strong passphrase and print it once")
		sf.Parse(args[1:])
		setPassphrase(st, *gen)
	case "device":
		device(st, args[1:])
	case "verify":
		if !verify(st) {
			os.Exit(1)
		}
	case "snapshot":
		if len(args) != 2 {
			flag.Usage()
			os.Exit(2)
		}
		if err := st.Snapshot(args[1]); err != nil {
			log.Fatal(err)
		}
	case "gc":
		gc(st, len(args) > 1 && args[1] == "-apply")
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func serve(st *Store, listen string) {
	srv := &http.Server{
		Addr:              listen,
		Handler:           NewServer(st).Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	log.Printf("obsyncd listening on %s", listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func device(st *Store, args []string) {
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	switch {
	case args[0] == "add":
		af := flag.NewFlagSet("device add", flag.ExitOnError)
		max := af.Int("max", maxDevices(), "active device limit if none is stored (default $OBSYNC_MAX_DEVICES, else 10)")
		af.Parse(args[1:])
		if af.NArg() != 1 {
			flag.Usage()
			os.Exit(2)
		}
		maxGiven := false
		af.Visit(func(f *flag.Flag) { maxGiven = maxGiven || f.Name == "max" })
		stored, err := st.DeviceLimit()
		if err != nil {
			log.Fatal(err)
		}
		limit, err := effectiveLimit(stored, maxGiven, *max)
		if err != nil {
			log.Fatal(err)
		}
		tok, err := st.AddDevice(af.Arg(0), limit)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(tok)
	case args[0] == "limit" && len(args) <= 2:
		if len(args) == 2 {
			n, err := strconv.Atoi(args[1])
			if err != nil || n < 0 {
				log.Fatal("usage: obsyncd device limit [N]   (0 removes the stored limit)")
			}
			if err := st.SetDeviceLimit(n); err != nil {
				log.Fatal(err)
			}
		}
		n, err := st.DeviceLimit()
		if err != nil {
			log.Fatal(err)
		}
		if n == 0 {
			fmt.Printf("no stored limit (device add uses -max, default %d)\n", maxDevices())
		} else {
			fmt.Printf("device limit: %d active devices\n", n)
		}
	case args[0] == "list":
		ds, err := st.Devices()
		if err != nil {
			log.Fatal(err)
		}
		for _, d := range ds {
			state := "active"
			if d.Revoked != 0 {
				state = "revoked " + time.Unix(d.Revoked, 0).Format(time.DateTime)
			}
			seen := "never"
			if d.LastSeen != 0 {
				seen = time.Unix(d.LastSeen, 0).Format(time.DateTime)
			}
			fmt.Printf("%-3d %-20s %-28s last seen %s\n", d.ID, d.Name, state, seen)
		}
	case args[0] == "revoke" && len(args) == 2:
		if err := st.RevokeDevice(args[1]); err != nil {
			log.Fatal(err)
		}
		fmt.Println("revoked")
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func verify(st *Store) bool {
	ok := true
	r, err := st.IntegrityCheck()
	if err != nil || r != "ok" {
		fmt.Printf("sqlite integrity_check: %v %s\n", err, r)
		ok = false
	}
	ref, err := st.ReferencedBlobs()
	if err != nil {
		log.Fatal(err)
	}
	seen := map[string]bool{}
	bad := 0
	err = st.blobs.Walk(func(sha, p string, info fs.FileInfo) error {
		seen[sha] = true
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != sha {
			fmt.Println("CORRUPT blob", sha)
			bad++
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	missing := 0
	for sha := range ref {
		if !seen[sha] {
			fmt.Println("MISSING blob", sha)
			missing++
		}
	}
	fmt.Printf("blobs: %d stored, %d referenced, %d corrupt, %d missing\n", len(seen), len(ref), bad, missing)
	return ok && bad == 0 && missing == 0
}

func gc(st *Store, apply bool) {
	ref, err := st.ReferencedBlobs()
	if err != nil {
		log.Fatal(err)
	}
	orphans, err := st.blobs.Orphans(ref, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range orphans {
		if apply {
			if err := os.Remove(p); err != nil {
				log.Fatal(err)
			}
		}
		fmt.Println(p)
	}
	verb := "would remove"
	if apply {
		verb = "removed"
	}
	fmt.Printf("%s %d unreferenced blobs\n", verb, len(orphans))
}

// setPassphrase makes the vault's key_check from a passphrase typed (or
// generated) here. Devices whose passphrase doesn't match it can't connect.
func setPassphrase(st *Store, generate bool) {
	v, err := st.Vault()
	if err != nil {
		log.Fatal("vault not initialised; run: obsyncd init")
	}
	if v.KeyCheck != "" {
		log.Fatal("the vault passphrase is already set and can't be changed")
	}
	var pass string
	switch {
	case generate:
		pass = generatePassphrase()
	case term.IsTerminal(int(os.Stdin.Fd())):
		fmt.Fprint(os.Stderr, "Vault passphrase: ")
		a, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprint(os.Stderr, "\nAgain: ")
		b, err2 := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil || err2 != nil {
			log.Fatal("could not read the passphrase")
		}
		if string(a) != string(b) {
			log.Fatal("the two entries differ")
		}
		pass = string(a)
	default:
		line, err := io.ReadAll(io.LimitReader(os.Stdin, 1024))
		if err != nil {
			log.Fatal(err)
		}
		pass = strings.TrimRight(string(line), "\r\n")
	}
	kc, err := makeKeyCheck(pass, v.KDFSalt, v.KDFIters)
	if err != nil {
		log.Fatal(err)
	}
	if !verifyKeyCheck(pass, v.KDFSalt, v.KDFIters, kc) {
		log.Fatal("internal error: key_check does not verify")
	}
	if err := st.SetKeyCheck(kc); err != nil {
		log.Fatal(err)
	}
	if generate {
		fmt.Printf("Vault passphrase (shown once; keep it in a password manager):\n\n    %s\n\n", pass)
	}
	fmt.Println("passphrase set. Enter it on each device in Settings -> Aizu Sync.")
}
