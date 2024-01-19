package kyberkem

import (
	"context"
	"errors"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/multiformats/go-multiaddr"
	"log"
	"os"
	"path"
	"sync"
	"time"
)

const hostname = "127.0.0.1"
const port = 4444

var currentVersion = 0

var NextVersion int = 0
var LastVersion uint64 = 0

var initializedOn time.Time

type InitLog struct {
	Content      string
	ErrorMessage string
}

var err error

func InitBooter() {

	err = nil
	if currentVersion == 0 {
		currentVersion = 1
	} else if currentVersion < 0 {
		err = errors.New("current version cannot be negative")
	} else {
		NextVersion = currentVersion + 1
		LastVersion = uint64(currentVersion - 1)
		initializedOn = time.Now()
		InitializeConfig(hostname, port)
	}
	if err != nil {
		err = WriteInitLog([]byte(err.Error()))
		panic(err)

	}

	_ = WriteInitLog([]byte("genovatix initialized"))

}

func WriteInitLog(data []byte) error {
	logPath := path.Join("logs", "init.log")
	log.Println(logPath)
	err := os.WriteFile(logPath, data, 0644)
	if err != nil {
		return err
	}
	return nil

}

func NewDHT(ctx context.Context, h host.Host, bootstrapPeers []multiaddr.Multiaddr) (kdht *dht.IpfsDHT, err error) {

	var options []dht.Option
	if len(bootstrapPeers) == 0 {
		options = append(options, dht.Mode(dht.ModeServer))
	}

	kdht, err = dht.New(ctx, h, options...)

	if err != nil {
		return nil, err
	}

	if err = kdht.Bootstrap(ctx); err != nil {
		return nil, err
	}

	var wg sync.WaitGroup

	for _, peerAddr := range bootstrapPeers {
		peerinfo, _ := peer.AddrInfoFromP2pAddr(peerAddr)
		wg.Add(1)

		go func() {
			defer wg.Done()
			if err := h.Connect(ctx, *peerinfo); err != nil {
				log.Printf("Error while connecting to node %q: %-v", peerinfo, err)
			} else {
				log.Printf("Connection established with bootstrap node: %q", *peerinfo)
			}
		}()
	}

	wg.Wait()

	return
}

func Discover(ctx context.Context, h host.Host, dht *dht.IpfsDHT) {
	var routingDiscovery = routing.NewRoutingDiscovery(dht)

	ns := Configuration.DefaultConfig.DiscoveryTagPrefix + Configuration.DefaultConfig.DiscoveryTagName
	routingDiscovery.Advertise(ctx, ns)
	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			peerAddr, err := routingDiscovery.FindPeers(ctx, ns)
			if err != nil {
				log.Fatal(err)
			}

			select {
			case <-peerAddr:

				p := <-peerAddr

				if p.ID == h.ID() {
					continue
				}
				if h.Network().Connectedness(p.ID) != network.Connected {
					_, err = h.Network().DialPeer(ctx, p.ID)

					if err.Error() == "empty peer ID" {
						return
					}

					if err != nil {
						log.Println(err)
						continue
					}
					log.Printf("Connected to peer %s\n", p.ID.String())
				}
			}

		}
	}

}
