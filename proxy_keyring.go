package main

import (
	"iter"
	"log/slog"
	"net"
	"slices"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type (
	proxyKeyring struct {
		mu      sync.Mutex
		sockets []string
	}
)

// Returns a new proxy key ring, safe to used by multiple goroutines.
func NewProxyKeyring(sockets []string) *proxyKeyring {
	return &proxyKeyring{
		sockets: sockets,
	}
}

// Iterates over all agents in a thread-safe manner
func (r *proxyKeyring) agents() iter.Seq[agent.ExtendedAgent] {
	return func(yield func(agent.ExtendedAgent) bool) {
		r.mu.Lock()
		defer r.mu.Unlock()

		for _, socket := range r.sockets {
			conn, err := net.Dial("unix", socket)
			if err != nil {
				slog.Error("error dialing", "socket", socket, "error", err)
				continue
			} else {
				defer func() { _ = conn.Close() }()

				if !yield(agent.NewClient(conn)) {
					return
				}
			}
		}
	}
}

// RemoveAll removes all identities.
func (r *proxyKeyring) RemoveAll() error {
	for a := range r.agents() {
		if err := a.RemoveAll(); err != nil {
			slog.Error("remove all", "error", err)
		}
	}

	return nil
}

// Remove removes all identities with the given public key.
func (r *proxyKeyring) Remove(key ssh.PublicKey) error {
	for a := range r.agents() {
		if err := a.Remove(key); err != nil {
			slog.Error("remove", "error", err)
		}
	}

	return nil
}

// Lock locks the agent. Sign and Remove will fail, and List will return an empty list.
func (r *proxyKeyring) Lock(passphrase []byte) error {
	for a := range r.agents() {
		if err := a.Lock(passphrase); err != nil {
			slog.Error("lock", "error", err)
		}
	}

	return nil
}

func (r *proxyKeyring) Unlock(passphrase []byte) error {
	for a := range r.agents() {
		if err := a.Unlock(passphrase); err != nil {
			slog.Error("unlock", "error", err)
		}
	}

	return nil
}

// List returns the identities known to the agent.
func (r *proxyKeyring) List() ([]*agent.Key, error) {
	var merged []*agent.Key

	for a := range r.agents() {
		if res, err := a.List(); err != nil {
			slog.Error("error listing", "error", err)
			continue
		} else {
			merged = slices.Concat(merged, res)
		}
	}

	return merged, nil
}

// Adds a private key to the keyring. If a certificate
// is given, that certificate is added as public key. Note that
// any constraints given are ignored.
func (r *proxyKeyring) Add(key agent.AddedKey) error {
	for a := range r.agents() {
		if err := a.Add(key); err != nil {
			slog.Error("error adding", "error", err)
			continue
		} else {
			// First add that succeeds is enough
			slog.Debug("key added", "comment", key.Comment)
			return nil
		}
	}

	return nil
}

// Sign returns a signature for the data.
func (r *proxyKeyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	for a := range r.agents() {
		if sig, err := a.Sign(key, data); err != nil {
			slog.Error("sign failed", "error", err)
		} else {
			return sig, nil
		}
	}

	return nil, nil
}

// Signers returns signers for all the known keys.
func (r *proxyKeyring) Signers() ([]ssh.Signer, error) {
	var merged []ssh.Signer

	for a := range r.agents() {
		if res, err := a.Signers(); err != nil {
			slog.Error("signers", "error", err)
			continue
		} else {
			merged = slices.Concat(merged, res)
		}
	}

	return merged, nil
}

// The keyring does not support any extensions
func (r *proxyKeyring) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
