package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	gossh "golang.org/x/crypto/ssh"

	"github.com/mikesmitty/edkey"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
)

func main() {
	authorizedKeysPathFlag := flag.String("authorized-keys", "", "path to authorized_keys file")

	flag.Parse()

	authorizedKeysPath := *authorizedKeysPathFlag
	if authorizedKeysPath == "" {
		log.Fatal("-authorized-keys option is required")
	}

	authorizedKeys, err := parseAuthorizedKeysFile(authorizedKeysPath)
	if err != nil {
		log.Fatal("failed to parse authorized keys file", err)
	}

	ssh.Handle(func(s ssh.Session) {
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
				if err != nil {
					panic(err)
				}

				fmt.Print(string(b))

				if _, err := s.Write(b); err != nil {
					panic(err)
				}
			}

			cmd.Wait()
		} else {
			io.WriteString(s, "No PTY requested.\n")
			s.Exit(1)
		}
	})

	pub, priv, err := generateKey()
	if err != nil {
		log.Fatal("failed to generate key", err)
	}

	privPEM := generatePrivateKeyPEM(priv)
	pubKey, err := gossh.NewPublicKey(pub)
	if err != nil {
		log.Fatal("failed to convert public key to ssh.PublicKey", err)
	}

	fmt.Println(pubKey.Type(), base64.StdEncoding.EncodeToString(pubKey.Marshal()))
	if err := ssh.ListenAndServe(":2222", nil, ssh.HostKeyPEM(privPEM),
		ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			fmt.Println("client trying", key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))

			for _, authorizedKey := range authorizedKeys {
				if ssh.KeysEqual(key, authorizedKey) {
					return true
				}
			}
			return false
		}),
	); err != nil {
		log.Fatal(err)
	}
}

func generateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func generatePrivateKeyPEM(priv ed25519.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: edkey.MarshalED25519PrivateKey(priv)})
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
