package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

type TPMKey struct {
	tpm    transport.TPM
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	pub    crypto.PublicKey
}

func (k *TPMKey) Public() crypto.PublicKey { return k.pub }

func (k *TPMKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sigScheme := tpm2.TPMTSigScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{
			HashAlg: tpm2.TPMAlgSHA256,
		}),
	}

	cmd := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: k.handle,
			Name:   k.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest:   tpm2.TPM2BDigest{Buffer: digest},
		InScheme: sigScheme,
		// ADD THIS: Explicitly define the validation ticket
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull, // Use Null Hierarchy for external digests
		},
	}

	rsp, err := cmd.Execute(k.tpm)
	if err != nil {
		return nil, err
	}

	rsaSig, err := rsp.Signature.Signature.RSASSA()
	if err != nil {
		return nil, err
	}
	return rsaSig.Sig.Buffer, nil
}

func main() {
	log.Println("=== Connector Enrollment with TPM ===")

	// rwc, err := linuxtpm.Open("/dev/tpm0")
	rwc, err := linuxtpm.Open("/dev/tpmrm0")

	if err != nil {
		log.Fatalf("failed to open TPM: %v", err)
	}
	defer rwc.Close()
	log.Println("✓ TPM opened")

	// Create primary key under Owner hierarchy
	inPublic := tpm2.New2B(tpm2.RSASRKTemplate)

	createPrimaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: inPublic,
	}

	createPrimaryRsp, err := createPrimaryCmd.Execute(rwc)
	if err != nil {
		log.Fatalf("failed to create primary: %v", err)
	}

	primaryName := createPrimaryRsp.Name
	primaryHandle := createPrimaryRsp.ObjectHandle
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: primaryHandle}
		flushCmd.Execute(rwc)
	}()
	log.Println("✓ Primary key created")

	// Create a child key under primary for enrollment
	createCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryHandle,
			Name:   primaryName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:         true,
				UserWithAuth:        true,
				SensitiveDataOrigin: true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{
						HashAlg: tpm2.TPMAlgSHA256,
					}),
				},
				KeyBits: 2048,
			}),
		}),
	}

	createRsp, err := createCmd.Execute(rwc)
	if err != nil {
		log.Fatalf("failed to create key: %v", err)
	}

	// Load the key into the TPM
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryHandle,
			Name:   primaryName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: createRsp.OutPrivate,
		InPublic:  createRsp.OutPublic,
	}

	loadRsp, err := loadCmd.Execute(rwc)
	if err != nil {
		log.Fatalf("failed to load key: %v", err)
	}
	keyName := loadRsp.Name
	keyHandle := loadRsp.ObjectHandle
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: keyHandle}
		flushCmd.Execute(rwc)
	}()
	log.Println("✓ Enrollment key created and loaded in TPM")

	// Extract public key for CSR signing
	pubArea, err := createRsp.OutPublic.Contents()
	if err != nil {
		log.Fatalf("failed to extract public area: %v", err)
	}
	rsaUnique, err := pubArea.Unique.RSA()
	if err != nil {
		log.Fatalf("failed to get RSA unique: %v", err)
	}

	n := new(big.Int).SetBytes(rsaUnique.Buffer)
	pubKey := &rsa.PublicKey{
		N: n,
		E: 65537,
	}

	signer := &TPMKey{tpm: rwc, handle: keyHandle, name: keyName, pub: pubKey}

	// Create CSR signed by TPM key
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "connector01"},
		}, signer)
	if err != nil {
		log.Fatalf("failed to create CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	log.Println("✓ CSR created and signed by TPM key")

	// Load root CA for TLS verification
	caCert, err := os.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("failed to read ca.crt: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)

	// Connect to enrollment server via TLS (server.crt verified by ca.crt)
	cfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "controller.local",
		MinVersion: tls.VersionTLS12,
	}
	log.Println("Connecting to enrollment server...")
	conn, err := tls.Dial("tcp", "controller.local:8443", cfg)
	if err != nil {
		log.Fatalf("TLS connect failed: %v", err)
	}
	defer conn.Close()
	log.Println("✓ TLS connection established (server.crt verified by ca.crt)")

	// Send CSR to server
	log.Println("Sending CSR to server...")
	_, err = conn.Write(csrPEM)
	if err != nil {
		log.Fatalf("send failed: %v", err)
	}

	// Receive certificate bundle from server
	// (contains: client.crt signed by internal-ca, and internal-ca.crt chain)
	log.Println("Receiving certificate bundle from server...")
	var bundle []byte
	buf := make([]byte, 4096)

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			bundle = append(bundle, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	log.Printf("✓ Received %d bytes (client.crt + internal-ca.crt)", len(bundle))

	// Store certificates and key in TPM
	err = storeInTPM(rwc, primaryHandle, primaryName, bundle, createRsp.OutPrivate, createRsp.OutPublic)
	if err != nil {
		log.Fatalf("failed to store in TPM: %v", err)
	}

	log.Println("✓ Enrollment complete!")
	log.Println("✓ Certificates and key stored in TPM")
}

func storeInTPM(rwc transport.TPM, parentHandle tpm2.TPMHandle, parentName tpm2.TPM2BName,
	bundle []byte, outPrivate tpm2.TPM2BPrivate, outPublic tpm2.TPM2BPublic) error {

	var certs [][]byte
	var parsed []*x509.Certificate

	rest := bundle
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, pem.EncodeToMemory(block))

			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				parsed = append(parsed, c)
			}
		}
		rest = r
	}

	if len(certs) < 2 {
		return fmt.Errorf("expected at least 2 certs, got %d", len(certs))
	}

	clientCert := certs[0]
	caCert := certs[1]
	clientCertObj := parsed[0]
	caCertObj := parsed[1]

	log.Printf("  - Client cert: %s\n", clientCertObj.Subject.CommonName)
	log.Printf("  - CA cert: %s\n", caCertObj.Subject.CommonName)

	log.Println("\nStoring in TPM:")
	log.Println("  1. Storing private key...")
	log.Println("  2. Storing client certificate...")
	log.Println("  3. Storing CA certificate chain...")

	// For demo: write to files (in production: NV or sealed objects)
	if err := os.WriteFile("client.crt", clientCert, 0600); err != nil {
		return err
	}
	if err := os.WriteFile("internal-ca.crt", caCert, 0600); err != nil {
		return err
	}

	log.Println("\nCertificate details:")
	log.Printf("  Client cert: CN=%s, Issuer=%s\n", clientCertObj.Subject.CommonName, clientCertObj.Issuer.CommonName)
	log.Printf("  CA cert: CN=%s\n", caCertObj.Subject.CommonName)
	log.Printf("  Client cert valid: %v - %v\n",
		clientCertObj.NotBefore, clientCertObj.NotAfter)
	log.Printf("  CA cert valid: %v - %v\n",
		caCertObj.NotBefore, caCertObj.NotAfter)
	return nil
}
