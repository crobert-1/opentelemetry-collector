// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configtls

import (
	"crypto/x509"
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func createReloader(t *testing.T) (*clientCAsFileReloader, *testLoader, string) {
	tmpClientCAsFilePath := createTempFile(t)
	loader := &testLoader{}
	reloader, _ := newClientCAsReloader(tmpClientCAsFilePath, loader)
	return reloader, loader, tmpClientCAsFilePath
}

func createTempFile(t *testing.T) string {
	tmpCa, err := os.CreateTemp("", "clientCAs.crt")
	assert.NoError(t, err)
	tmpCaPath, err := filepath.Abs(tmpCa.Name())
	assert.NoError(t, err)
	assert.NoError(t, tmpCa.Close())
	return tmpCaPath
}

type testLoader struct {
	err     atomic.Value
	counter atomic.Uint32
}

func (r *testLoader) loadClientCAFile() (*x509.CertPool, error) {
	r.counter.Add(1)

	v := r.err.Load()
	if v == nil {
		return nil, nil
	}

	return nil, v.(error)
}

func (r *testLoader) returnErrorOnSubsequentCalls(msg string) {
	r.err.Store(fmt.Errorf(msg))
}

func (r *testLoader) reloadNumber() int {
	return int(r.counter.Load())
}
