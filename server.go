package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

type oneTimeServer struct {
	once       sync.Once
	lasOnce    sync.Once
	server     *ssh.Server
	sessionErr error
	timeout    time.Duration
}

func newOneTimeServer(addr string, authorizedKeys []gossh.PublicKey, signer ssh.Signer,
	logWriter io.Writer, copyEnv bool, timeout time.Duration) *oneTimeServer {
	server := &ssh.Server{
		Addr: addr,
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			for _, authorizedKey := range authorizedKeys {
				if ssh.KeysEqual(key, authorizedKey) {
					return true
				}
			}
			return false
		},
	}

	ots := oneTimeServer{
		server:  server,
		timeout: timeout,
	}

	server.Handle(func(s ssh.Session) {
		ots.once.Do(func() {
			logNotice(fmt.Sprintf("session connected from %v", s.RemoteAddr()))
			ots.sessionErr = handleSSHSession(logWriter, copyEnv, s)
			logNotice("session disconnected")
			server.Close()
		})
	})

	server.AddHostKey(signer)
	return &ots
}

func (ots *oneTimeServer) ListenAndServe(ctx context.Context) error {
	var g errgroup.Group

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	g.Go(func() error {
		select {
		case <-time.After(ots.timeout):
			ots.once.Do(func() {
				logWarn(fmt.Sprintf("no connection within supplied timeout (%v), exiting\n", ots.timeout))
				ots.Close()
			})
		case <-cctx.Done():
		}
		return nil
	})

	err := ots.server.ListenAndServe()
	return err
}

func (ots *oneTimeServer) Close() error {
	return ots.server.Close()
}

func (ots *oneTimeServer) SessionError() error {
	return ots.sessionErr
}

func handleSSHSession(logWriter io.Writer, copyEnv bool, s ssh.Session) error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "bash"
	}

	cmd := exec.Command(shell)

	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		io.WriteString(s, "No PTY requested.\n")
		return nil
	}

	if copyEnv {
		cmd.Env = append(cmd.Env, os.Environ()...)
	}

	cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	f, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("failed to start pty: %w", err)
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
			return fmt.Errorf("failed to read from command: %w", err)
		}

		if _, err := logWriter.Write(b); err != nil {
			return fmt.Errorf("failed to write to log: %w", err)
		}

		if _, err := s.Write(b); err != nil {
			return fmt.Errorf("failed to write to session: %w", err)
		}
	}

	return cmd.Wait()
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}
