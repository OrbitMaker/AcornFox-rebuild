//go:build !darwin && !linux

package dockerfile

import "errors"

func readRootDockerfileNoFollow(string) ([]byte, bool, error) {
	return nil, false, errors.New("unsupported")
}
