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
	"os"
	"os/exec"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/mikesmitty/edkey"

	"github.com/gliderlabs/ssh"
)

func main() {
	authorizedKeysPathFlag := flag.String("authorized-keys", "", "path to authorized_keys file. stdin will be used if not passed.")
	announceCmdFlag := flag.String("announce", "", "command which will be run with the generated public key")
	copyEnvFlag := flag.Bool("copy-env", true, "copy environment to ssh sessions (default true)")
	logPathFlag := flag.String("log", "otssh.log", "path to log to")
	timeoutFlag := flag.Int("timeout", 600, "timeout in seconds")
	portFlag := flag.String("port", "2022", "port to listen on")

	flag.Parse()

	authorizedKeysPath := *authorizedKeysPathFlag
	if authorizedKeysPath == "" {
		logNotice("-authorized-keys not passed: reading authorized keys from stdin")
	}

	announceCmd := *announceCmdFlag
	copyEnv := *copyEnvFlag
	logPath := *logPathFlag
	timeout := *timeoutFlag
	port := *portFlag

	if err := run(authorizedKeysPath, announceCmd, logPath, port, timeout, copyEnv); err != nil {
		code := 0

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ProcessState.ExitCode()
		}

		logError(err.Error())
		os.Exit(code)
	}
}

func run(authorizedKeysPath, announceCmd, logPath, port string, timeout int, copyEnv bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
			logWarn(fmt.Sprintf("announcement failed: %v", err))
			logWarn(fmt.Sprintf("stderr from announcement: %v", stderr))
		}
	}

	timeoutDuration := time.Duration(timeout) * time.Second

	logSuccess("Starting server listening on :" + port + ". The server will use the following key:")
	server := newOneTimeServer(":"+port, authorizedKeys, signer, logFile, copyEnv, timeoutDuration)

	fmt.Printf("\n%v\n\n", formatKnownHosts(pubKey))

	if err = server.ListenAndServe(ctx); err != nil {
		if errors.Is(err, ssh.ErrServerClosed) {
			return nil
		}

		return err
	}

	if err := server.Close(); err != nil {
		return fmt.Errorf("failed to ")
	}

	return server.SessionError()
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
	f := os.Stdin
	if path != "" {
		var err error
		f, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %w", err)
		}
	}

	var keys []gossh.PublicKey

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		bytes := scanner.Bytes()
		if len(keys) == 0 && len(bytes) == 0 {
			return nil, fmt.Errorf("no keys supplied - either pass a file using -authorized-keys, or pipe them in")
		}

		key, _, _, _, err := gossh.ParseAuthorizedKey(bytes)
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
