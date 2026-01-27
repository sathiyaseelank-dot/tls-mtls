// controller.go
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

var db = map[string]map[string]string{} // fingerprint -> attributes
var caCert *x509.Certificate
var caKey crypto.PrivateKey

func main() {
	// Load CA certificate and key
	caCertFile, err := os.ReadFile("internal-ca.crt")
	if err != nil {
		log.Fatalf("failed to read ca certificate: %v", err)
	}
	caCertBlock, _ := pem.Decode(caCertFile)
	caCert, err = x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		log.Fatalf("failed to parse ca certificate: %v", err)
	}

	caKeyFile, err := os.ReadFile("internal-ca.key")
	if err != nil {
		log.Fatalf("failed to read ca key: %v", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyFile)
	caKey, err = x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		log.Fatalf("failed to parse ca key: %v", err)
	}

	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load server key pair: %v", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
	}

	ln, err := tls.Listen("tcp", ":8443", cfg)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Println("Enrollment server running")

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v", err)
			continue
		}
		go handleEnroll(c)
	}
}

func handleEnroll(c net.Conn) {
	defer c.Close()

	data := make([]byte, 8192)
	n, err := c.Read(data)
	if err != nil {
		log.Printf("failed to read from connection: %v", err)
		return
	}
	data = data[:n]

	block, _ := pem.Decode(data)
	if block == nil {
		log.Printf("failed to decode PEM block")
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		log.Printf("failed to parse CSR: %v", err)
		return
	}

	if err := csr.CheckSignature(); err != nil {
		log.Printf("CSR signature validation failed: %v", err)
		return
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		log.Printf("failed to marshal public key: %v", err)
		return
	}
	fp := sha256.Sum256(pubBytes)
	fingerprint := hex.EncodeToString(fp[:])

	db[fingerprint] = map[string]string{
		"role": "connector",
		"zone": "prod",
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Printf("failed to generate serial number: %v", err)
		return
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, csr.PublicKey, caKey)
	if err != nil {
		log.Printf("failed to create certificate: %v", err)
		return
	}

	clientCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCertBytes,
	})

	caRaw, _ := os.ReadFile("internal-ca.crt")

	// Ensure CA is valid PEM
	var caBlocks []byte
	rest := caRaw
	for {
		b, r := pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			caBlocks = append(caBlocks, pem.EncodeToMemory(b)...)
		}
		rest = r
	}

	// Final bundle: client + full CA chain
	bundle := append(clientCertPEM, caBlocks...)

	_, err = c.Write(bundle)
	if err != nil {
		log.Printf("failed to write response: %v", err)
	}

}
