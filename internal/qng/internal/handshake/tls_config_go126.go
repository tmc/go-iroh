package handshake

import (
	tls "github.com/tmc/go-iroh/internal/itls/tls"
	"net"
)

// go-iroh: upstream selects between this file and a go1.27 variant that uses
// tls.QUICConfig.ClientHelloInfoConn, added to the standard library in Go 1.27.
// The fork drives internal/itls/tls, a copy of Go 1.26's crypto/tls, so the
// toolchain version says nothing about whether that field exists: it does not,
// at any Go version. This file is therefore unconditional and the go1.27
// variant is dropped. Restore the split if itls gains ClientHelloInfoConn.
func setupConfigForClient(conf *tls.Config) *tls.Config {
	conf = conf.Clone()
	conf.MinVersion = tls.VersionTLS13
	return conf
}

func setupConfigForServer(conf *tls.Config, localAddr, remoteAddr net.Addr) *tls.Config {
	// Workaround for https://github.com/golang/go/issues/60506.
	// This initializes the session tickets _before_ cloning the config.
	_, _ = conf.DecryptTicket(nil, tls.ConnectionState{})

	conf = conf.Clone()
	conf.MinVersion = tls.VersionTLS13

	// The tls.Config contains two callbacks that pass in a tls.ClientHelloInfo.
	// Since crypto/tls doesn't do it, we need to make sure to set the Conn field with a fake net.Conn
	// that allows the caller to get the local and the remote address.
	if conf.GetConfigForClient != nil {
		gcfc := conf.GetConfigForClient
		conf.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			info.Conn = &conn{localAddr: localAddr, remoteAddr: remoteAddr}
			c, err := gcfc(info)
			if c != nil {
				// we're returning a tls.Config here, so we need to apply this recursively
				c = setupConfigForServer(c, localAddr, remoteAddr)
			}
			return c, err
		}
	}
	if conf.GetCertificate != nil {
		gc := conf.GetCertificate
		conf.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			info.Conn = &conn{localAddr: localAddr, remoteAddr: remoteAddr}
			return gc(info)
		}
	}
	return conf
}

func getQUICConfig(tlsConf *tls.Config, _, _ net.Addr) *tls.QUICConfig {
	return &tls.QUICConfig{
		TLSConfig:           tlsConf,
		EnableSessionEvents: true,
	}
}
