package stdout

import (
	"os"
	"sync"
)

type StdoutOutput struct {
	mu sync.Mutex
}

func (f *StdoutOutput) Write(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	_, err := os.Stdout.Write(b)
	return err
}

func (f *StdoutOutput) Close() error {
	return nil
}
