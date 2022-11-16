package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"io"
	"os"
)

var (
	decryptConfig = &DecryptConfig{
		PrivatePath:     "private.key",
		ContentEncoding: "",
		Mode:            "c1c3c2",
	}
)

type DecryptConfig struct {
	PrivatePath     string
	EncryptedFile   string
	ContentEncoding string
	Mode            string
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "sm2 数据解密",
	Run: func(cmd *cobra.Command, args []string) {

		privateKey, err := loadPrivateKey(decryptConfig)
		if err != nil {
			panic(err)
		}

		var fileData []byte
		if decryptConfig.EncryptedFile == "-" {
			fileData, err = io.ReadAll(os.Stdin)
		} else {
			fileData, err = os.ReadFile(decryptConfig.EncryptedFile)
		}
		if err != nil {
			panic(err)
		}

		var encryptedData []byte
		switch decryptConfig.ContentEncoding {
		case "base64":
			encryptedData, err = base64.StdEncoding.DecodeString(string(fileData))
			if err != nil {
				panic(err)
			}
		case "bcd":
			encryptedData = ascToBCD(fileData, len(fileData))
		case "hex":
			encryptedData, err = hex.DecodeString(string(fileData))
			if err != nil {
				panic(err)
			}
		default:
			encryptedData = fileData
		}

		var decryptedData []byte
		switch decryptConfig.Mode {
		case "asn1":
			decryptedData, err = sm2.DecryptAsn1(privateKey, encryptedData)
			if err != nil {
				panic(err)
			}
		case "c1c2c3":
			decryptedData, err = sm2.Decrypt(privateKey, encryptedData, sm2.C1C2C3)
			if err != nil {
				panic(err)
			}

		case "c1c3c2":
			decryptedData, err = sm2.Decrypt(privateKey, encryptedData, sm2.C1C3C2)
			if err != nil {
				panic(err)
			}
		default:
			panic(fmt.Errorf("不支持的mode %v", decryptConfig.Mode))
		}

		fmt.Println(string(decryptedData))
	},
}

func loadPrivateKey(config *DecryptConfig) (*sm2.PrivateKey, error) {
	pri, err := os.ReadFile(config.PrivatePath)
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ReadPrivateKeyFromPem(pri, nil)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func init() {
	f := decryptCmd.Flags()

	f.StringVarP(&decryptConfig.PrivatePath, "private-key", "k", decryptConfig.PrivatePath, "配置私有Key")
	f.StringVarP(&decryptConfig.EncryptedFile, "input", "i", decryptConfig.EncryptedFile, "待解密的文件路径,-表示从标准输入读取")
	f.StringVarP(&decryptConfig.ContentEncoding, "content-encoding", "c", decryptConfig.ContentEncoding, "待解密的文件内容编码，默认直接使用。 base64,hex,bcd")
	f.StringVarP(&decryptConfig.Mode, "mode", "m", decryptConfig.Mode, "配置加密格式 asn1,c1c2c3,c1c3c2")

	_ = decryptCmd.MarkFlagRequired("private-key")
	_ = decryptCmd.MarkFlagRequired("encrypted-file")
}

func ascToBCD(ascii []byte, length int) []byte {
	bcd := make([]byte, length/2)
	j := 0
	for i := 0; i < (length+1)/2; i++ {

		bcd[i] = asciiToBCD(ascii[j])
		j += 1
		if j >= length {
			bcd[i] = 0x00
		} else {
			bcd[i] = asciiToBCD(ascii[j]) + (bcd[i] << 4)
			j += 1
		}
	}

	return bcd
}

func asciiToBCD(asc byte) byte {
	var bcd byte
	if (asc >= '0') && (asc <= '9') {
		bcd = asc - '0'
	} else if (asc >= 'A') && (asc <= 'F') {
		bcd = asc - 'A' + 10
	} else if (asc >= 'a') && (asc <= 'f') {
		bcd = asc - 'a' + 10
	} else {
		bcd = asc - 48
	}
	return bcd
}
