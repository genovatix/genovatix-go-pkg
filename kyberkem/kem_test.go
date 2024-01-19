package kyberkem

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/libp2p/go-libp2p"
	netmock "github.com/libp2p/go-libp2p-testing/net"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	_ "go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/util/random"
	"net"
	"testing"
	"time"
)

type MockConn struct {
	buffer bytes.Buffer
}

// Implement net.Conn interface

func generateID() (net netmock.Identity) {
	net, _ = netmock.RandIdentity()
	return
}

func (mc *MockConn) Read(b []byte) (n int, err error) {
	return mc.buffer.Read(b)
}

func (mc *MockConn) Write(b []byte) (n int, err error) {
	return mc.buffer.Write(b)
}

func (mc *MockConn) Close() error {
	return nil
}

func (mc *MockConn) LocalAddr() net.Addr {
	return nil
}

func (mc *MockConn) RemoteAddr() net.Addr {
	return nil
}

func (mc *MockConn) SetDeadline(t time.Time) error {
	return nil
}

func (mc *MockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (mc *MockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func populateGST(t *testing.T, gst *GenovatixSecureTransport) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)
	gst.suite = suite
	gst.publicKey = public
	gst.privateKey = private
}

func makeRandomHost(t *testing.T, port int) (host.Host, error) {
	priv, _, err := crypto.GenerateKeyPair(crypto.KyberKey, 2048)
	require.NoError(t, err)

	return libp2p.New([]libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port)),
		libp2p.Identity(priv),
		libp2p.DefaultTransports,
		libp2p.DefaultMuxers,
		libp2p.Security("genovatix", NewGenovatixSecureTransport),
		libp2p.NATPortMap(),
	}...)
}

func TestSecureInbound(t *testing.T) {

	//a, b := mock.MockConnections(t)
	server := MockSecureHostServer(t)

	MockClientAndConnect(t, server)

}

func TestEstablishSecureConnection(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	gst := &GenovatixSecureTransport{
		suite: suite,
	}
	secret := suite.Scalar().Pick(suite.RandomStream())
	point := suite.Point().Mul(secret, nil)
	_, err := gst.establishSecureConnection(point)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewSecureConn(t *testing.T) {
	conn := &MockConn{}
	peer1 := peer.ID("first")
	peer2 := peer.ID("second")
	aesBlock, err := aes.NewCipher([]byte("super secret key"))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(aesBlock)
	if err != nil {
		t.Fatal(err)
	}
	_, pubKey, _ := crypto.GenerateKeyPair(crypto.KyberKey, 2048)
	connState := NewConnectedState()
	wrapper := NewSecureConn(conn, aead, peer1, peer2, pubKey, connState)
	if wrapper == nil {
		t.Fatal("wrapper is nil")
	}
	if wrapper.aead.NonceSize() != aead.NonceSize() {
		t.Fatalf("want: %v, got: %v", aead.NonceSize(), wrapper.aead.NonceSize())
	}
}

func NewConnectedState() network.ConnectionState {
	return network.ConnectionState{
		StreamMultiplexer:         "/yamux/1.0.0", // Example value
		Security:                  "/tls/1.2.0",   // Example value
		Transport:                 "tcp",          // Example value
		UsedEarlyMuxerNegotiation: false,          // Example value
	}
}

func TestReadKey(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	public := suite.Point().Pick(suite.RandomStream())
	pk := crypto.KyberPublicKey{
		Pub:   public,
		Suite: suite,
	}
	conn := &MockConn{}
	defer conn.Close()
	_, err := pk.Pub.MarshalTo(&conn.buffer)
	if err != nil {
		t.Fatal(err)
	}
	point, err := readKey(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !point.Equal(public) {
		t.Fatal("points are not equal")
	}
}

func TestGenerateSharedSecret(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	private := suite.Scalar().Pick(suite.RandomStream())
	public := suite.Point().Pick(suite.RandomStream())
	pointA := generateSharedSecret(private, public)
	pointB := suite.Point().Mul(private, public)
	if !pointA.Equal(pointB) {
		t.Fatal("points are not equal")
	}
}
