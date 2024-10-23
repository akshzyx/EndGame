package main

import (
	"crypto/ed25519"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gobalance/pkg/brand"
	"gobalance/pkg/onionbalance"
	"gobalance/pkg/stem/descriptor"
	_ "golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
)

// https://onionbalance.readthedocs.io
// https://github.com/torproject/torspec/blob/main/control-spec.txt
// https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt

var appVersion = "1.0.0"

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	logrus.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

	app := &cli.App{
		Name:    "gobalance",
		Usage:   "Golang rewrite of onionbalance",
		Authors: []*cli.Author{{Name: "n0tr1v", Email: "n0tr1v@protonmail.com"}, {Name: "Paris", Email: "amazingsights@inter.net(Not Real)"}},
		Version: appVersion,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "ip",
				Aliases: []string{"i"},
				Usage:   "Tor control IP address",
				Value:   "127.0.0.1",
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Usage:   "Tor control port",
				Value:   9051,
			},
			&cli.StringFlag{
				Name:    "torPassword",
				Aliases: []string{"tor-password"},
				Usage:   "Tor control password",
			},
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Config file location",
				Value:   "config.yaml",
			},
			&cli.BoolFlag{
				Name:    "quick",
				Aliases: []string{"q"},
				Usage:   "Quickly publish a new descriptor (for HSDIR descriptor failures/tests)",
			},
			&cli.BoolFlag{
				Name:    "adaptive",
				Aliases: []string{"a"},
				Usage: "Adaptive publishing changes the way descriptors are published to prioritize descriptor rotation on the HSDIR. " +
					"A counter to introduction cell attacks (with enough scale) and a more private version of introduction spamming. The default is true.",
				Value: true,
			},
			&cli.BoolFlag{
				Name:    "tight",
				Aliases: []string{"t"},
				Usage: "Use tight adaptive descriptor timings. This is effectively a safe version of introduction spamming. " +
					"Most useful in the case of DDOS. Strains and potentially crashes the Tor process. The default is false.",
				Value: false,
			},
			&cli.BoolFlag{
				Name:    "strict",
				Aliases: []string{"s"},
				Usage:   "Strictly adhere to adaptive algorithms and, at the start, panic if non-optimal conditions are found. The default is false.",
				Value:   false,
			},
			&cli.StringFlag{
				Name:    "dirsplit",
				Aliases: []string{"ds"},
				Usage: "'Responsible HSDIR split' splits the descriptor submission to the network." +
					"Allowing for multiple gobalance processes to work as a single noncompetitive unit. " +
					"This allows for more flexible scaling on fronts as many Tor processes can be safely used. " +
					"Valid values are ranges (like 1-2 or 3-8). Cover all ranges from 1-8 on all processes! The default is 1-8.",
				Value: "1-8",
			},
			&cli.StringFlag{
				Name:    "verbosity",
				Aliases: []string{"vv"},
				Usage:   "Minimum verbosity level for logging. Available in ascending order: debug, info, warning, error, critical). The default is info.",
				Value:   "info",
			},
		},
		Action: mainAction,
		Commands: []*cli.Command{
			{
				Name:    "generate-config",
				Aliases: []string{"g"},
				Usage:   "generate a config.yaml file",
				Action:  generateConfigAction,
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		logrus.Fatal(err)
	}
}

func mainAction(c *cli.Context) error {
	verbosity := c.String("verbosity")

	logLvl := logrus.InfoLevel
	switch verbosity {
	case "debug":
		logLvl = logrus.DebugLevel
	case "info":
		logLvl = logrus.InfoLevel
	case "warning":
		logLvl = logrus.WarnLevel
	case "error":
		logLvl = logrus.ErrorLevel
	case "critical":
		logLvl = logrus.FatalLevel
	default:
		panic("Invalid 'verbosity' value. Valid values are: debug, info, warning, error, critical.")
	}
	logrus.SetLevel(logLvl)

	logrus.Warningf("Initializing gobalance (version: %s)...", appVersion)
	onionbalance.Main(c)
	select {}
}

func fileExists(filePath string) bool {
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func generateConfigAction(*cli.Context) error {
	/*
		Enter path to store generated config
		Number of services (frontends) to create (default: 1):
		Enter path to master service private key (i.e. path to 'hs_ed25519_secret_key') (Leave empty to generate a key)
		Number of instance services to create (default: 2) (min: 1, max: 8)
		Provide a tag name to group these instances [node]

		Done! Successfully generated OnionBalance config
		Now please edit 'config/config.yaml' with a text editor to add/remove/edit your backend instances
	*/
	configFilePath, _ := filepath.Abs("./config.yaml")
	if fileExists(configFilePath) {
		logrus.Fatalf("config file %s already exists", configFilePath)
	}

	masterPublicKey, masterPrivateKey, _ := ed25519.GenerateKey(brand.Reader())
	masterPrivateKeyDer, _ := x509.MarshalPKCS8PrivateKey(masterPrivateKey)
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: masterPrivateKeyDer}
	onionAddress := descriptor.AddressFromIdentityKey(masterPublicKey)
	masterKeyFileName := strings.TrimSuffix(onionAddress, ".onion") + ".key"
	masterKeyFile, err := os.Create(masterKeyFileName)
	if err != nil {
		logrus.Fatal(err)
	}
	defer func(masterKeyFile *os.File) {
		err := masterKeyFile.Close()
		if err != nil {
			logrus.Fatal(err)
		}
	}(masterKeyFile)
	_ = pem.Encode(masterKeyFile, block)

	configFile, err := os.Create(configFilePath)
	if err != nil {
		logrus.Fatal(err)
	}
	defer func(configFile *os.File) {
		err := configFile.Close()
		if err != nil {
			logrus.Fatal(err)
		}
	}(configFile)
	data := onionbalance.ConfigData{
		Services: []onionbalance.ServiceConfig{{
			Key:       masterKeyFileName,
			Instances: []onionbalance.InstanceConfig{{Address: "<Enter the instance onion address here>"}},
		}},
	}
	if err := yaml.NewEncoder(configFile).Encode(data); err != nil {
		logrus.Fatal(err)
	}
	return nil
}
