package kyberkem

import (
	"context"
	"encoding/json"
	"github.com/libp2p/go-libp2p/core/crypto/pb"
	"os"
	"time"
)

type Params struct{}

type DefaultParams struct {
	DiscoveryInterval  time.Duration `json:"discovery_interval"`
	DiscoveryTagPrefix string        `json:"discovery_tag_prefix"`
	DiscoveryTagName   string        `json:"discovery_tag_name"`
	KeyType            pb.KeyType
	Context            context.Context
	DHTProtocolPrefix  string `json:"dht_protocol_prefix"`
	Version            string
	BootstrapPeers     []string `json:"bootstrap_peers"`
	Hostname           string
	Port               int
}

type Config struct {
	DefaultConfig *DefaultParams
	OldConfig     *Config
	ConfigVersion uint64
	LastVersion   uint64
	UpdatedOn     int64
}

var Configuration Config

func InitializeConfig(hostname string, port int) {
	config, err := readJsonConfig()
	if err != nil {
		panic(err)
	}
	Configuration = Config{DefaultConfig: config, OldConfig: &Config{}, ConfigVersion: 1, LastVersion: 0, UpdatedOn: 0}
	Configuration.DefaultConfig.KeyType = pb.KeyType_KyberKey
	Configuration.DefaultConfig.Context = context.Background()
	Configuration.DefaultConfig.Version = "1"
	Configuration.DefaultConfig.Hostname = hostname
	Configuration.DefaultConfig.Port = port
	Configuration.DefaultConfig.DiscoveryInterval = Configuration.DefaultConfig.DiscoveryInterval * time.Minute

}

func readJsonConfig() (*DefaultParams, error) {
	jsonFile := "config.json"
	fileBytes, _ := os.ReadFile(jsonFile)
	var config DefaultParams
	err := json.Unmarshal(fileBytes, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
