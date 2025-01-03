package main

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

var (
	mkr *proxyKeyring
)

func check(err error) {
	if err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func init() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	slog.SetDefault(logger)
}

func cleanup(fp *os.File) {
	name := fp.Name()
	_ = fp.Close()
	_ = os.Remove(name)
}

func handler(conn net.Conn) {
	slog.Info("client accepted")

	if err := agent.ServeAgent(mkr, conn); err != nil && !errors.Is(err, io.EOF) {
		slog.Error("serve agent", "error", err)
	}

	_ = conn.Close()
}

func main() {
	if len(os.Args) < 2 {
		slog.Error("fatal", "error", "no auth sockets specified")
		os.Exit(1)
	}

	mkr = NewProxyKeyring(os.Args[1:])

	fp, err := os.CreateTemp(os.TempDir(), "multi-ssh-agent-*")
	check(err)

	name := fp.Name()
	cleanup(fp)

	slog.Info("starting", "SSH_AUTH_SOCK", name, "sockets", mkr.sockets)

	socket, err := net.Listen("unix", name)
	check(err)

	for {
		// Accept an incoming connection.
		conn, err := socket.Accept()
		if err != nil {
			slog.Error("accept", "error", err)
			continue
		}

		go handler(conn)
	}
}
