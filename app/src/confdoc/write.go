package confdoc

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// Write saves every changed document atomically. The old text of an existing
// file is first copied to backupDir/<name>-<timestamp>.yaml. A file that
// changed on disk since the set was read is not overwritten.
func (s *Set) Write(backupDir string, now time.Time) ([]string, error) {
	changed := s.Changed()
	data := make([][]byte, len(changed))
	for i, d := range changed {
		b, err := d.Bytes()
		if err != nil {
			return nil, err
		}
		data[i] = b
		cur, err := os.ReadFile(d.Path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if d.Exists {
				return nil, fmt.Errorf("%s was removed since it was read; reload and try again", d.ID)
			}
		case err != nil:
			return nil, err
		case !d.Exists || !bytes.Equal(cur, d.orig):
			return nil, fmt.Errorf("%s changed on disk since it was read; reload and try again", d.ID)
		}
	}
	var written []string
	for i, d := range changed {
		if err := projectfile.Write(d.Path, data[i], backupDir, now); err != nil {
			return written, err
		}
		written = append(written, d.Path)
	}
	return written, nil
}
