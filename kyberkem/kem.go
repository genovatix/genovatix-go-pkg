package kyberkem

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"github.com/libp2p/go-libp2p/core/network"
	"io"

	"crypto/cipher"
	"encoding/binary"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"

	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/util/encoding"
	"net"
)

type GenovatixSecureTransport struct {
	suite     suites.Suite
	seed      []byte
	publicKey kyber.Point

	privateKey kyber.Scalar
}

func setSuite(g *GenovatixSecureTransport) {
	g.suite = edwards25519.NewBlakeSHA256Ed25519()
}

// ID returns the protocol ID
func (g *GenovatixSecureTransport) ID() protocol.ID {
	return "genovatix protocol"
}

// SecureInbound establishes a secure inbound connection. It takes a network connection
// and the peer ID, and returns a secure connection or error.
func (g *GenovatixSecureTransport) SecureInbound(ctx context.Context, insecure net.Conn, peerID peer.ID) (sec.SecureConn, error) {
	remotePubKey, err := readKey(insecure)
	if err != nil {
		return nil, err
	}
	sharedSecret := generateSharedSecret(g.privateKey, remotePubKey)
	secureConn, err := g.establishSecureConnection(sharedSecret)
	if err != nil {
		return nil, err
	}

	return secureConn, nil
}

// establishSecureConnection creates and returns a secure connection using the shared secret.
// Further implementation is needed based on project specifics.
func (g *GenovatixSecureTransport) establishSecureConnection(sharedSecret kyber.Point) (sec.SecureConn, error) {
	var secureConn sec.SecureConn
	// Your logic to establish a secure connection using the shared secret goes here...
	return secureConn, nil
}

// readKey reads a public key from the given connection
func readKey(conn net.Conn) (kyber.Point, error) {
	// Use bufio.Reader for more efficient reading
	r := bufio.NewReader(conn)

	// First, read the length of the serialized key
	var size uint32
	err := binary.Read(r, binary.BigEndian, &size)
	if err != nil {
		return nil, err
	}

	suite := edwards25519.NewBlakeSHA256Ed25519()

	pb, err := encoding.ReadHexPoint(suite, r)
	if err != nil {
		return nil, err
	}
	return crypto.KyberPublicKey{
		Pub:   pb,
		Suite: suite,
	}.Pub, nil
}

// SecureOutbound UpgradeOutbound upgrades an outbound connection
func (g *GenovatixSecureTransport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	// Implement your key exchange mechanism here for outbound connections
	// Return a SecureConn which is a net.Conn wrapped with encryption
	return nil, nil
}

func NewGenovatixSecureTransport() *GenovatixSecureTransport {

	gst := &GenovatixSecureTransport{}
	setSuite(gst)

	return gst
}

func generateSharedSecret(myKey kyber.Scalar, peerKey kyber.Point) kyber.Point {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	SA := suite.Point().Mul(myKey, peerKey)
	return SA
}

type SecureConnWrapper struct {
	net.Conn
	aead            cipher.AEAD
	localPeer       peer.ID
	remotePeer      peer.ID
	remotePublicKey crypto.PubKey
	connState       network.ConnectionState
}

func (s *SecureConnWrapper) LocalPeer() peer.ID {
	return s.localPeer
}

func (s *SecureConnWrapper) RemotePeer() peer.ID {
	return s.remotePeer
}

func (s *SecureConnWrapper) RemotePublicKey() crypto.PubKey {
	return s.remotePublicKey
}

func (s *SecureConnWrapper) ConnState() network.ConnectionState {
	return s.connState
}

func NewSecureConn(conn net.Conn, aead cipher.AEAD, localPeer peer.ID, remotePeer peer.ID, remotePublicKey crypto.PubKey, connState network.ConnectionState) *SecureConnWrapper {
	return &SecureConnWrapper{
		Conn:            conn,
		aead:            aead,
		localPeer:       localPeer,
		remotePeer:      remotePeer,
		remotePublicKey: remotePublicKey,
		connState:       connState,
	}
}

func (s *SecureConnWrapper) Read(b []byte) (n int, err error) {
	buffer := make([]byte, s.aead.NonceSize()+len(b))
	_, err = s.Conn.Read(buffer)
	if err != nil {
		return 0, err
	}

	nonce, ciphertext := buffer[:s.aead.NonceSize()], buffer[s.aead.NonceSize():]
	plainText, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, err
	}

	n = copy(b, plainText)
	return n, nil
}

func (s *SecureConnWrapper) Write(b []byte) (n int, err error) {
	nonce := make([]byte, s.aead.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return 0, err
	}

	ciphertext := s.aead.Seal(nonce, nonce, b, nil)
	return s.Conn.Write(ciphertext)
}

func setupEncryptedConnection(sharedSecret kyber.Point, conn net.Conn,
	localPeer peer.ID, remotePeer peer.ID, remotePublicKey crypto.PubKey, connState network.ConnectionState) (sec.SecureConn, error) {
	sharedSecretBytes, err := sharedSecret.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal binary: %w", err)

	}

	block, err := aes.NewCipher(sharedSecretBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create block cipher: %w", err)

	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm: %w", err)

	}

	return NewSecureConn(conn, aead, localPeer, remotePeer, remotePublicKey, connState), nil
}
