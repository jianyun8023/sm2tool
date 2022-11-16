package cmd

import (
	"crypto/rand"
	"github.com/spf13/cobra"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"os"
)

var (
	keypairConfig = &KeypairConfig{
		PrivateKey: "private.key",
		PublicKey:  "public.key",
	}
)

type KeypairConfig struct {
	PrivateKey string
	PublicKey  string
}

var keypairCmd = &cobra.Command{
	Use:   "keypair",
	Short: "生成sm2的密钥对",
	Run: func(cmd *cobra.Command, args []string) {

		privateKey, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		publicKey := &privateKey.PublicKey

		privatePem, err := x509.WritePrivateKeyToPem(privateKey, nil)
		publicPem, err := x509.WritePublicKeyToPem(publicKey)

		err = os.WriteFile(keypairConfig.PrivateKey, privatePem, 777)
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(keypairConfig.PublicKey, publicPem, 777)
		if err != nil {
			panic(err)
		}
	},
}

func init() {
	f := keypairCmd.Flags()
	f.StringVarP(&keypairConfig.PrivateKey, "private-key", "k", keypairConfig.PrivateKey, "配置PrivateKey路径")
	f.StringVarP(&keypairConfig.PublicKey, "public-key", "p", keypairConfig.PublicKey, "配置PublicKey路径")
}
