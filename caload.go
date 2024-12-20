package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func getClusterCA(ctx context.Context, client client.Client) (*x509.Certificate, error) {
	// Get the kube-root-ca.crt ConfigMap that exists in each namespace
	cm := &corev1.ConfigMap{}
	err := client.Get(ctx, types.NamespacedName{
		Name:      "kube-root-ca.crt",
		Namespace: "kube-system",
	}, cm)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA ConfigMap: %w", err)
	}

	// The CA cert is stored in the "ca.crt" key
	caCertPEM, ok := cm.Data["ca.crt"]
	if !ok {
		return nil, fmt.Errorf("ca.crt not found in ConfigMap")
	}

	// Decode PEM block
	block, _ := pem.Decode([]byte(caCertPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	// Parse the CA certificate
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return caCert, nil
}

// loadCA loads the Kubernetes cluster CA certificate and private key
func loadCA() (*x509.Certificate, interface{}, error) {
	// Default paths for Kubernetes CA files
	caCertPath := "/etc/kubernetes/pki/ca.crt"
	caKeyPath := "/etc/kubernetes/pki/ca.key"

	// Load CA certificate
	caCertPEM, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA cert file: %v", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to parse certificate PEM")
	}

	// Parse the CA certificate
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Load CA private key
	caKeyPEM, err := ioutil.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA key file: %v", err)
	}

	// Decode PEM block
	block, _ = pem.Decode(caKeyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to parse key PEM")
	}

	// Parse the private key
	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %v", err)
	}

	return caCert, caKey, nil
}

// Helper function to verify CA certificate
func verifyCA(caCert *x509.Certificate) error {
	// Create a new certificate pool
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	// Verify the certificate
	if _, err := caCert.Verify(opts); err != nil {
		return fmt.Errorf("CA certificate verification failed: %v", err)
	}

	return nil
}

// Example usage of loading and using the CA for signing
func signUserCertificate(username, email string) error {
	// Load the CA certificate and private key
	fmt.Print()
	caCert, caKey, err := loadCA()
	if err != nil {
		return fmt.Errorf("failed to load CA: %v", err)
	}

	// Verify the CA certificate
	if err := verifyCA(caCert); err != nil {
		return fmt.Errorf("CA verification failed: %v", err)
	}

	// Create certificate template for user
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   email,
			Organization: []string{"authenticated"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Generate user's private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		caCert,
		&privateKey.PublicKey,
		caKey,
	)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode certificate and private key in PEM format
	certOut := &bytes.Buffer{}
	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	keyOut := &bytes.Buffer{}
	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Save the certificate and private key
	certPath := filepath.Join("/etc/kubernetes/pki/users", fmt.Sprintf("%s.crt", username))
	keyPath := filepath.Join("/etc/kubernetes/pki/users", fmt.Sprintf("%s.key", username))

	if err := ioutil.WriteFile(certPath, certOut.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	if err := ioutil.WriteFile(keyPath, keyOut.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}

	return nil
}

// Utility function to check if a certificate is valid
func isCertificateValid(certPath string) (bool, error) {
	// Read the certificate file
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return false, fmt.Errorf("failed to read certificate: %v", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, fmt.Errorf("failed to parse certificate PEM")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Check if the certificate is expired
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false, nil
	}

	// Load CA certificate for verification
	caCert, _, err := loadCA()
	if err != nil {
		return false, fmt.Errorf("failed to load CA: %v", err)
	}

	// Create certificate pool with CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Verify the certificate
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		return false, nil
	}

	return true, nil
}
