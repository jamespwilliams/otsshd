package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"

	"github.com/mikesmitty/edkey"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
)

func main() {
	// TODO: allow stdin:
	authorizedKeysPathFlag := flag.String("authorized-keys", "", "path to authorized_keys file")
	announceCmdFlag := flag.String("announce", "", "command which will be run with the generated public key")
	logPathFlag := flag.String("log", "otssh.log", "path to log to")
	timeoutFlag := flag.Int("timeout", 600, "timeout in seconds")
	portFlag := flag.String("port", "2022", "port to listen on")

	flag.Parse()

	announceCmd := *announceCmdFlag
	logPath := *logPathFlag
	timeout := *timeoutFlag
	port := *portFlag

	authorizedKeysPath := *authorizedKeysPathFlag
	if authorizedKeysPath == "" {
		log.Fatal("otssh: -authorized-keys option is required")
	}

	if err := run(authorizedKeysPath, announceCmd, logPath, port, timeout); err != nil {
		log.Fatal("otssh:", err)
	}
}

func run(authorizedKeysPath, announceCmd, logPath, port string, timeout int) error {
	ctx := context.Background()

	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open log file at %v: %w", logPath, err)
	}

	authorizedKeys, err := parseAuthorizedKeysFile(authorizedKeysPath)
	if err != nil {
		return fmt.Errorf("failed to parse authorized keys file: %w", err)
	}

	pub, priv, err := generateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	privPEM := generatePrivateKeyPEM(priv)
	signer, err := gossh.ParsePrivateKey(privPEM)
	if err != nil {
		return fmt.Errorf("failed to convert private key to format expected by ssh server: %w", err)
	}

	pubKey, err := gossh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("failed to convert public key to ssh.PublicKey: %w", err)
	}

	if announceCmd != "" {
		if stderr, err := performAnnouncement(announceCmd, pubKey); err != nil {
			log.Print("announcement failed:", err)
			log.Print("stderr from announcement:", stderr)
		}
	}

	fmt.Println(formatKnownHosts(pubKey))

	server := &ssh.Server{
		Addr: ":" + port,
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			fmt.Println("client trying", key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))

			for _, authorizedKey := range authorizedKeys {
				if ssh.KeysEqual(key, authorizedKey) {
					return true
				}
			}
			return false
		},
	}

	// We use the same once for handling the session and shutting down the server, because we don't want to shut
	// down the server when the timeout is hit if there's a live session:
	var once sync.Once
	server.Handle(func(s ssh.Session) {
		once.Do(func() {
			handleSession(logFile, s)
			server.Shutdown(ctx)
		})
	})

	server.AddHostKey(signer)

	var g errgroup.Group
	g.Go(func() error {
		err := server.ListenAndServe()
		if errors.Is(err, ssh.ErrServerClosed) {
			return nil
		}
		return err
	})

	g.Go(func() error {
		select {
		case <-time.After(time.Duration(timeout) * time.Second):
			log.Printf("otssh: no connection within %v seconds, exiting\n", timeout)
			once.Do(func() {
				server.Shutdown(ctx)
			})
		}
		return nil
	})

	return g.Wait()
}

func generateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func generatePrivateKeyPEM(priv ed25519.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: edkey.MarshalED25519PrivateKey(priv)})
}

func formatKnownHosts(key ssh.PublicKey) string {
	return fmt.Sprintf("%v %s", key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))
}

func performAnnouncement(command string, key ssh.PublicKey) (stderr string, err error) {
	args := strings.Fields(command)
	args = append(args, formatKnownHosts(key))
	_, err = exec.Command(args[0], args[1:]...).Output()
	if err != nil {
		var eerr *exec.ExitError
		if errors.As(err, &eerr) {
			return string(eerr.Stderr), err
		}
		return "", err
	}
	return "", nil
}

func parseAuthorizedKeysFile(path string) ([]gossh.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	var keys []gossh.PublicKey

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, _, _, _, err := gossh.ParseAuthorizedKey(scanner.Bytes())
		if err != nil {
			return nil, fmt.Errorf("failed to parse key on line %v: %w", len(keys), err)
		}

		keys = append(keys, key)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning file failed: %w", err)
	}

	return keys, nil
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func handleSession(logW io.Writer, s ssh.Session) {
	cmd := exec.Command("bash")
	ptyReq, winCh, isPty := s.Pty()
	if isPty {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		f, err := pty.Start(cmd)
		if err != nil {
			panic(err)
		}
		go func() {
			for win := range winCh {
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			io.Copy(f, s)
		}()

		r := bufio.NewReaderSize(f, 1024)
		for {
			b := make([]byte, 1024)
			_, err := r.Read(b)

			if _, ok := err.(*os.PathError); ok {
				break
			}

			if err != nil {
				log.Fatal(err)
			}

			if _, err := logW.Write(b); err != nil {
				// TODO: handle this better...
				log.Fatal(err)
			}

			if _, err := s.Write(b); err != nil {
				fmt.Printf("%#v\n", err)
				log.Fatal(err)
			}
		}

		cmd.Wait()
	} else {
		io.WriteString(s, "No PTY requested.\n")
	}
}
