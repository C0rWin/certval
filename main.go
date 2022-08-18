package main

import (
	"certval/utils"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use: "certval --certFile certFile --caFile caFile --sanitizeCerts",
		Run: func(cmd *cobra.Command, args []string) {
			validate()
		},
	}
	rootCAFile string
	certFile   string
	sanitize   bool
)

func main() {
	rootCmd.Flags().StringVarP(&rootCAFile, "caFile", "", "", "root ca file (required)")
	rootCmd.MarkFlagRequired("caFile")
	rootCmd.Flags().StringVarP(&certFile, "certFile", "", "", "x509 certificate file (required)")
	rootCmd.MarkFlagRequired("certFile")
	rootCmd.Flags().BoolVar(&sanitize, "sanitizeCerts", false, "whenever to sanitize cert files")
	rootCmd.Execute()
}

func validate() {
	certpool := x509.NewCertPool()

	caFileBytes, err := os.ReadFile(rootCAFile)
	if err != nil {
		panic(err)
	}

	caPemBlock, _ := pem.Decode(caFileBytes)
	caCert, err := x509.ParseCertificate(caPemBlock.Bytes)
	if err != nil {
		panic(err)
	}

	if isECDSASignedCert(caCert) && sanitize {
		caCert, err = utils.SanitizeCert(caCert)
		if err != nil {
			panic(err)
		}
	}

	certpool.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots: certpool,
	}

	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		panic(err)
	}

	certPemBlock, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(certPemBlock.Bytes)
	if err != nil {
		panic(err)
	}

	_, err = cert.Verify(opts)
	if err != nil {
		panic(err)
	}

	fmt.Println("SUCCESS")
}

func isECDSASignedCert(cert *x509.Certificate) bool {
	return cert.SignatureAlgorithm == x509.ECDSAWithSHA1 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA256 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA384 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA512
}
