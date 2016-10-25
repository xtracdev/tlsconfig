package tlsconfig

import (
	"io/ioutil"
	"crypto/x509"
	"crypto/tls"
)

func LoadCertificates(privateKeyFile, certificateFile, caFile string) (tls.Certificate, *x509.CertPool) {

	mycert, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		panic(err)
	}

	pem, err := ioutil.ReadFile(caFile)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pem) {
		panic("Failed appending certs")
	}

	return mycert, certPool

}

func GetTlsConfiguration(privateKeyFile, certificateFile, caFile string) *tls.Config {
	config := &tls.Config{}
	mycert, certPool := LoadCertificates(privateKeyFile, certificateFile, caFile)
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
	return config
}
