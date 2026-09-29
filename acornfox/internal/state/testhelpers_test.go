package state

import (
	"io/fs"
	"os"
)

// statMode returns the file mode of path, for permission assertions in tests.
func statMode(path string) (fs.FileMode, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Mode(), nil
}
