// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configtls // import "go.opentelemetry.io/collector/config/configtls"

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
)

type clientCAsFileReloader struct {
	clientCAsFile   string
	certPool        *x509.CertPool
	lastReloadError error
	lock            sync.RWMutex
	loader          clientCAsFileLoader
	reload          bool
}

type clientCAsFileLoader interface {
	loadClientCAFile() (*x509.CertPool, error)
}

func newClientCAsReloader(clientCAsFile string, loader clientCAsFileLoader) (*clientCAsFileReloader, error) {
	certPool, err := loader.loadClientCAFile()
	if err != nil {
		return nil, fmt.Errorf("failed to load client CA CertPool: %w", err)
	}

	reloader := &clientCAsFileReloader{
		clientCAsFile: clientCAsFile,
		certPool:      certPool,
		loader:        loader,
	}

	return reloader, nil
}

func (r *clientCAsFileReloader) enableReloadClientCAFile() {
	r.reload = true
}

func (r *clientCAsFileReloader) getClientConfig(original *tls.Config) (*tls.Config, error) {
	if r.reload {
		r.lock.Lock()
		defer r.lock.Unlock()

		certPool, err := r.loader.loadClientCAFile()
		if err == nil {
			r.certPool = certPool
		}
	}

	return &tls.Config{
		RootCAs:              original.RootCAs,
		GetCertificate:       original.GetCertificate,
		GetClientCertificate: original.GetClientCertificate,
		MinVersion:           original.MinVersion,
		MaxVersion:           original.MaxVersion,
		NextProtos:           original.NextProtos,
		ClientCAs:            r.certPool,
		ClientAuth:           tls.RequireAndVerifyClientCert,
	}, nil
}
