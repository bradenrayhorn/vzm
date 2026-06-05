package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	caOnce sync.Once
	caErr  error
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte

	leafCertCache sync.Map
)

func certificateAuthorityPEM() ([]byte, error) {
	if err := initCertificateAuthority(); err != nil {
		return nil, err
	}
	return append([]byte(nil), caPEM...), nil
}

func writeCertificateAuthorityPEMToWorkingDir() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}

	path := filepath.Join(cwd, "mitm-ca.crt.pem")
	return path, writeCertificateAuthorityPEMToPath(path)
}

func writeCertificateAuthorityPEMToPath(path string) error {
	pemBytes, err := certificateAuthorityPEM()
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		return fmt.Errorf("write certificate PEM: %w", err)
	}

	return nil
}

func generateFakeCertForDomain(domain string) (tls.Certificate, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		domain = "localhost"
	}

	if cert, ok := leafCertCache.Load(domain); ok {
		return cert.(tls.Certificate), nil
	}

	if err := initCertificateAuthority(); err != nil {
		return tls.Certificate{}, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"VZM MITM"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(domain); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{domain}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create leaf certificate: %w", err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	leafKeyBytes, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal leaf key: %w", err)
	}
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyBytes})

	cert, err := tls.X509KeyPair(leafCertPEM, leafKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load key pair: %w", err)
	}

	leafCertCache.Store(domain, cert)
	return cert, nil
}

func initCertificateAuthority() error {
	caOnce.Do(func() {
		var key *ecdsa.PrivateKey
		key, caErr = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if caErr != nil {
			return
		}

		serial, err := randomSerialNumber()
		if err != nil {
			caErr = err
			return
		}

		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				CommonName:   "VZM MITM Root CA",
				Organization: []string{"VZM"},
			},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLenZero:        true,
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			caErr = fmt.Errorf("create root certificate: %w", err)
			return
		}

		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			caErr = fmt.Errorf("parse root certificate: %w", err)
			return
		}

		caCert = cert
		caKey = key
		caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	})
	return caErr
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	if serial.Sign() == 0 {
		return randomSerialNumber()
	}
	return serial, nil
}

func init() {
	if err := initCertificateAuthority(); err != nil {
		log.Printf("proxy certificate authority initialization failed: %v", err)
	}
}
