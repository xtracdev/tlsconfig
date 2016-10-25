package tlsconfig

import (
	"io/ioutil"
	"crypto/x509"
	"crypto/tls"
	"errors"
)

func LoadCertificates(privateKeyFile, certificateFile, caFile string) (tls.Certificate, *x509.CertPool, error) {

	var mycert tls.Certificate
	mycert, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return mycert, nil, err
	}

	pem, err := ioutil.ReadFile(caFile)
	if err != nil {
		return mycert, nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pem) {
		return mycert, nil, errors.New("Unable to append certs from PEM")
	}

	return mycert, certPool, nil

}

func GetTlsConfiguration(privateKeyFile, certificateFile, caFile string) (*tls.Config, error) {
	config := &tls.Config{}
	mycert, certPool, err := LoadCertificates(privateKeyFile, certificateFile, caFile)
	if err != nil {
		return nil, err
	}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = mycert

	config.RootCAs = certPool
	config.ClientCAs = certPool

	config.ClientAuth = tls.RequireAndVerifyClientCert

	// Causes servers to use Go's default ciphersuite preferences,
	// which are tuned to avoid attacks. Does nothing on clients.
	config.PreferServerCipherSuites = true

	// Only use curves which have constant-time implementations
	config.CurvePreferences = []tls.CurveID{
		tls.CurveP256,
	}

	//Use only TLS v1.2
	config.MinVersion = tls.VersionTLS12

	//Don't allow session resumption
	config.SessionTicketsDisabled = true
	return config,nil
}
