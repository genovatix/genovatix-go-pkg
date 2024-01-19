package kyberkem

import (
	"context"
	"crypto/rand"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func MockConnections(t *testing.T) (net.Conn, net.Conn) {
	lstnr, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err, "failed to listen")

	var clientErr error
	var client net.Conn
	done := make(chan struct{})

	go func() {
		defer close(done)
		addr := lstnr.Addr()
		client, clientErr = net.Dial(addr.Network(), addr.String())
	}()

	server, err := lstnr.Accept()
	require.NoError(t, err, "failed to accept")

	<-done
	lstnr.Close()
	require.NoError(t, clientErr, "failed to connect")
	return client, server
}

func MockSecureTransport(t *testing.T) sec.SecureTransport {
	return NewGenovatixSecureTransport()
}

func MockPeer(t *testing.T) (peer.ID, crypto.PrivKey) {
	var priv crypto.PrivKey
	var err error
	priv, _, err = crypto.GenerateKeyPair(crypto.KyberKey, 2048)
	require.NoError(t, err)
	id, err := peer.IDFromPrivateKey(priv)
	require.NoError(t, err)
	t.Logf("using a %s key: %s", priv.Type(), id)
	return id, priv
}

func MockSecureHostServer(t *testing.T) host.Host {
	serverID, _, err := crypto.GenerateKyberKey(rand.Reader)
	require.NoError(t, err)
	server, err := libp2p.New(libp2p.Identity(serverID),
		libp2p.Security("/genovatix", NewGenovatixSecureTransport),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
	)
	require.NoError(t, err)
	return server
}

func MockClientAndConnect(t *testing.T, server host.Host) {
	defer server.Close()
	clientID, _, err := crypto.GenerateKyberKey(rand.Reader)
	require.NoError(t, err)
	client, err := libp2p.New(
		libp2p.Identity(clientID),
		libp2p.Security("/genovatix", NewGenovatixSecureTransport),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.NoListenAddrs,
	)
	require.NoError(t, err)

	err = client.Connect(context.Background(), peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()})
	require.NoError(t, err)
	conns := client.Network().ConnsToPeer(server.ID())
	require.Len(t, conns, 1, "expected exactly one connection")
	require.Equal(t, "/genovatix", conns[0].ConnState().Security)
}
