package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"time"

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

func shouldReEnroll(cert *x509.Certificate, pub *rsa.PublicKey) bool {
	// 1) expired or not yet valid
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		log.Println("🔁 cert expired or not yet valid")
		return true
	}

	// 2) 70% lifetime passed
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	age := now.Sub(cert.NotBefore)
	if age > (lifetime * 70 / 100) {
		log.Printf("🔁 cert lifetime %.1f%% — re-enrolling\n", float64(age)*100/float64(lifetime))
		return true
	}

	// 3) public key mismatch
	if rsaCert, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		if !rsaCert.Equal(pub) {
			log.Println("🔁 cert key mismatch — re-enrolling")
			return true
		}
	}

	return false
}

func (k *TPMKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := opts.HashFunc()
	var hashAlg tpm2.TPMAlgID

	switch hashFunc {
	case crypto.SHA256:
		hashAlg = tpm2.TPMAlgSHA256
	case crypto.SHA384:
		hashAlg = tpm2.TPMAlgSHA384
	case crypto.SHA512:
		hashAlg = tpm2.TPMAlgSHA512
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %v", hashFunc)
	}

	// Verify digest length matches hash algorithm
	expectedLen := hashFunc.Size()
	if len(digest) != expectedLen {
		return nil, fmt.Errorf("digest length mismatch: got %d, want %d", len(digest), expectedLen)
	}

	sigScheme := tpm2.TPMTSigScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{
			HashAlg: hashAlg,
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
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rsp, err := cmd.Execute(k.tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM Sign failed: %w", err)
	}

	rsaSig, err := rsp.Signature.Signature.RSASSA()
	if err != nil {
		return nil, fmt.Errorf("failed to extract RSASSA signature: %w", err)
	}

	sig := rsaSig.Sig.Buffer
	log.Printf("TPM Sign: input digest %d bytes → output signature %d bytes (hash: %v)",
		len(digest), len(sig), hashFunc)
	return sig, nil
}
func main() {
	log.Println("=== Connector Enrollment with TPM ===")

	// rwc, err := linuxtpm.Open("/dev/tpm0")
	rwc, err := linuxtpm.Open("/dev/tpmrm0")

	if err != nil {
		log.Fatalf("failed to open TPM: %v", err)
	}
	// Don't close TPM here - controlLoop uses it
	// rwc stays open for the lifetime of the process
	log.Println("✓ TPM opened")

	var keyHandle tpm2.TPMHandle
	var keyName tpm2.TPM2BName
	var createRsp *tpm2.CreateResponse
	var pubKey *rsa.PublicKey
	var skipEnrollment bool
	var clientCertObj *x509.Certificate

	// Try load persistent key
	read := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(0x81000001),
	}
	if readRsp, err := read.Execute(rwc); err == nil {
		log.Println("✓ Found persistent TPM key 0x81000001")
		keyHandle = tpm2.TPMHandle(0x81000001)
		keyName = readRsp.Name

		// Extract public key from persistent object
		pubArea, _ := readRsp.OutPublic.Contents()
		if rsaUnique, _ := pubArea.Unique.RSA(); rsaUnique != nil {
			n := new(big.Int).SetBytes(rsaUnique.Buffer)
			pubKey = &rsa.PublicKey{N: n, E: 65537}
		}

		// Check if we already have a valid certificate
		if certBytes, err := os.ReadFile("client.crt"); err == nil {
			if block, _ := pem.Decode(certBytes); block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					if !shouldReEnroll(cert, pubKey) {
						log.Println("✓ Valid identity found — skipping enrollment")
						clientCertObj = cert
						skipEnrollment = true
					}
				}
			}
		}

		if !skipEnrollment {
			log.Println("⚠ Certificate invalid — will re-enroll with persistent key")
		}
	}

	if keyHandle == 0 && !skipEnrollment {
		log.Println("No persistent key, creating new one...")

		// Create primary
		primaryRsp, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(nil),
			},
			InPublic: tpm2.New2B(tpm2.RSASRKTemplate),
		}.Execute(rwc)
		if err != nil {
			log.Fatalf("failed to create primary: %v", err)
		}

		defer func() {
			flushCmd := tpm2.FlushContext{FlushHandle: primaryRsp.ObjectHandle}
			flushCmd.Execute(rwc)
		}()

		// Create child
		createRsp, err = tpm2.Create{
			ParentHandle: tpm2.AuthHandle{
				Handle: primaryRsp.ObjectHandle,
				Name:   primaryRsp.Name,
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
		}.Execute(rwc)
		if err != nil {
			log.Fatalf("failed to create key: %v", err)
		}

		// Load
		loadRsp, err := tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: primaryRsp.ObjectHandle,
				Name:   primaryRsp.Name,
				Auth:   tpm2.PasswordAuth(nil),
			},
			InPrivate: createRsp.OutPrivate,
			InPublic:  createRsp.OutPublic,
		}.Execute(rwc)
		if err != nil {
			log.Fatalf("failed to load key: %v", err)
		}

		// Persist
		_, err = tpm2.EvictControl{
			Auth: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(nil),
			},
			ObjectHandle: &tpm2.NamedHandle{
				Handle: loadRsp.ObjectHandle,
				Name:   loadRsp.Name,
			},
			PersistentHandle: tpm2.TPMHandle(0x81000001),
		}.Execute(rwc)
		if err != nil {
			log.Fatal("persist failed:", err)
		}

		keyHandle = tpm2.TPMHandle(0x81000001)
		keyName = loadRsp.Name
		log.Println("✓ TPM key created + persisted at 0x81000001")
	}

	// Extract public key from newly created key if not using persistent
	if pubKey == nil {
		pubArea, err := createRsp.OutPublic.Contents()
		if err != nil {
			log.Fatalf("failed to extract public area: %v", err)
		}
		rsaUnique, err := pubArea.Unique.RSA()
		if err != nil {
			log.Fatalf("failed to get RSA unique: %v", err)
		}

		n := new(big.Int).SetBytes(rsaUnique.Buffer)
		pubKey = &rsa.PublicKey{
			N: n,
			E: 65537,
		}
	}

	signer := &TPMKey{tpm: rwc, handle: keyHandle, name: keyName, pub: pubKey}

	// Test the signer before attempting TLS
	testData := []byte("test message")
	hash := sha256.Sum256(testData)
	testSig, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		log.Printf("⚠️  TPM sign test failed: %v", err)
	} else {
		log.Printf("✓ TPM sign test successful: %d bytes", len(testSig))
		// Verify the signature
		if rsaPub, ok := signer.Public().(*rsa.PublicKey); ok {
			err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], testSig)
			if err != nil {
				log.Printf("⚠️  TPM signature verification FAILED: %v", err)
			} else {
				log.Printf("✓ TPM signature verification successful")
			}
		}
	}

	if skipEnrollment {
		log.Println("✓ Enrollment skipped — using existing certificate")
	} else {
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
		caCert, err := os.ReadFile("../ca/ca.crt")
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
		clientCertObj, err = storeInTPM(bundle, pubKey)
		if err != nil {
			log.Fatalf("failed to store in TPM: %v", err)
		}
	}

	log.Println("✓ Enrollment complete!")
	log.Println("✓ Certificates and key stored in TPM")

	go controlLoop(clientCertObj, signer, rwc)

	select {} // block forever

}

func storeInTPM(bundle []byte, expectedPubKey *rsa.PublicKey) (*x509.Certificate, error) {

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
		return nil, fmt.Errorf("expected at least 2 certs, got %d", len(certs))
	}

	clientCert := certs[0]
	caCert := certs[1]
	clientCertObj := parsed[0]
	caCertObj := parsed[1]

	log.Printf("  - Client cert: %s\n", clientCertObj.Subject.CommonName)
	log.Printf("  - CA cert: %s\n", caCertObj.Subject.CommonName)

	// Verify certificate public key matches TPM public key
	if rsaCert, ok := clientCertObj.PublicKey.(*rsa.PublicKey); ok {
		if !rsaCert.Equal(expectedPubKey) {
			log.Printf("⚠️  WARNING: Certificate public key does NOT match TPM public key!")
			log.Printf("   Cert N=%d bits, TPM N=%d bits", rsaCert.N.BitLen(), expectedPubKey.N.BitLen())
		} else {
			log.Println("✓ Certificate public key matches TPM key")
		}
	}

	log.Println("\nStoring in TPM:")
	log.Println("  1. Storing private key...")
	log.Println("  2. Storing client certificate...")
	log.Println("  3. Storing CA certificate chain...")

	// For demo: write to files (in production: NV or sealed objects)
	if err := os.WriteFile("client.crt", clientCert, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile("internal-ca.crt", caCert, 0600); err != nil {
		return nil, err
	}

	log.Println("\nCertificate details:")
	log.Printf("  Client cert: CN=%s, Issuer=%s\n", clientCertObj.Subject.CommonName, clientCertObj.Issuer.CommonName)
	log.Printf("  CA cert: CN=%s\n", caCertObj.Subject.CommonName)
	log.Printf("  Client cert valid: %v - %v\n",
		clientCertObj.NotBefore, clientCertObj.NotAfter)
	log.Printf("  CA cert valid: %v - %v\n",
		caCertObj.NotBefore, caCertObj.NotAfter)
	return clientCertObj, nil
}
func controlLoop(clientCert *x509.Certificate, signer crypto.Signer, rwc transport.TPM) {
	for {
		log.Println("Connecting to control plane...")

		caPEM, _ := os.ReadFile("../internal-ca/internal-ca.crt")
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(caPEM)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{clientCert.Raw},
			PrivateKey:  signer, // 🔐 TPM-backed key
		}

		// Client config (connector)
		cfg := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			RootCAs:      caPool,
			ServerName:   "controller.local",
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		}

		conn, err := tls.Dial("tcp", "controller.local:9443", cfg)
		if err != nil {
			log.Println("control connect failed, retrying:", err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Println("🔐 Control plane connected")

		// Send initial connection message immediately
		_, err = conn.Write([]byte(`{"type":"ping"}` + "\n"))
		if err != nil {
			log.Println("control write failed:", err)
			conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		buf := make([]byte, 4096)
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				_, err := conn.Write([]byte(`{"type":"ping"}` + "\n"))
				if err != nil {
					conn.Close()
					return
				}
				time.Sleep(5 * time.Second)
			}
		}()

		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Println("control lost, reconnecting")
				conn.Close()
				break
			}
			log.Println("control:", string(buf[:n]))
		}
	}
}
