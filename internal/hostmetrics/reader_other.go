//go:build !linux

package hostmetrics

import "errors"

type unsupportedReader struct{}

func defaultReader() Reader { return unsupportedReader{} }

func (unsupportedReader) ReadFile(string, int64) ([]byte, error) {
	return nil, errors.New("unsupported")
}
func (unsupportedReader) Statfs(string) (Filesystem, error) {
	return Filesystem{}, errors.New("unsupported")
}
