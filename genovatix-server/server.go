package genovatix_server

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/genovatix/genovatix-go-pkg/kyberkem"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/multiformats/go-multiaddr"
	"log"
	"os"
)

func StartDHTServer() {
	kyberkem.InitializeConfig("127.0.0.1", 4444)
	kyberkem.InitBooter()
	spew.Dump(kyberkem.Configuration)
	ctx := context.Background()
	kyberPrivKey, _, err := crypto.GenerateKyberKey(rand.Reader)

	if err != nil {
		log.Fatalf("Failed to generate Kyber private key: %s", err)
	}

	h, err := libp2p.New(libp2p.Identity(kyberPrivKey), libp2p.Security("genovatix", kyberkem.NewGenovatixSecureTransport), libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))

	if err != nil {
		log.Fatalf("failed to start host: %s", err)
	}

	// view host details and addresses
	log.Printf("host ID %s\n", h.ID().String())
	log.Printf("following are the assigned addresses\n")
	for _, addr := range h.Addrs() {
		fmt.Printf("%s\n", addr.String())
	}
	log.Printf("\n")

	gossipSub, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		log.Fatal("failed to start gossip sub")
	}

	var discoveryPeers = make([]multiaddr.Multiaddr, 0)
	dht, err := kyberkem.NewDHT(ctx, h, discoveryPeers)
	if err != nil {
		log.Fatal("failed to start dht server")
	}
	go kyberkem.Discover(ctx, h, dht)

	// setup local mDNS discovery
	if err := setupDiscovery(h); err != nil {
		panic(err.Error())
	}

	topic, err := gossipSub.Join("welcome")
	if err != nil {
		panic(err)
	}

	publish(ctx, topic)
	select {}
}

// start publisher to topic
func publish(ctx context.Context, topic *pubsub.Topic) {
	for {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			fmt.Printf("enter message to publish: \n")

			msg := scanner.Text()
			if len(msg) != 0 {
				// publish message to topic
				bytes := []byte(msg)
				topic.Publish(ctx, bytes)
			}
		}
	}
}

// discoveryNotifee gets notified when we find a new peer via mDNS discovery
type discoveryNotifee struct {
	h host.Host
}

// HandlePeerFound connects to peers discovered via mDNS. Once they're connected,
// the PubSub system will automatically start interacting with them if they also
// support PubSub.
func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	fmt.Printf("discovered new peer %s\n", pi.ID.String())
	err := n.h.Connect(context.Background(), pi)
	if err != nil {
		fmt.Printf("error connecting to peer %s: %s\n", pi.ID.String(), err)
	}
}

// setupDiscovery creates an mDNS discovery service and attaches it to the libp2p Host.
// This lets us automatically discover peers on the same LAN and connect to them.
func setupDiscovery(h host.Host) error {
	// setup mDNS discovery to find local peers
	s := mdns.NewMdnsService(h, kyberkem.Configuration.DefaultConfig.DiscoveryTagPrefix+kyberkem.Configuration.DefaultConfig.DiscoveryTagName, &discoveryNotifee{h: h})

	return s.Start()
}
