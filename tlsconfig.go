package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
)

func loadCertificates(privateKeyFile, certificateFile, caCertFile string) (tls.Certificate, *x509.CertPool, error) {

	var certificate tls.Certificate
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return certificate, nil, err
	}

	pem, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return certificate, nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pem) {
		return certificate, nil, errors.New("Unable to append certs from PEM")
	}

	return certificate, certPool, nil

}

//GetTLSConfiguration produces a strong TLS configuration that supports MTLS that can be used
//for both the client and server sides on communication using TLS.
func GetTLSConfiguration(privateKeyFile, certificateFile, caFile string) (*tls.Config, error) {
	config := &tls.Config{}
	certificate, certPool, err := loadCertificates(privateKeyFile, certificateFile, caFile)
	if err != nil {
		return nil, err
	}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = certificate

	config.RootCAs = certPool
	config.ClientCAs = certPool

	config.ClientAuth = tls.RequireAndVerifyClientCert

	// Causes servers to use Go's default cipher suite preferences,
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
	return config, nil
}
