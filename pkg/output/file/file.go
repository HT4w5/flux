package file

import (
	"os"
	"sync"
)

type FileOutput struct {
	file *os.File
	mu   sync.Mutex

	// Config
	path string
	mode os.FileMode
}

func New(opts ...func(*FileOutput)) (*FileOutput, error) {
	f := &FileOutput{
		mode: 0644, // Default file mode
	}

	for _, opt := range opts {
		opt(f)
	}

	// Open the file if path is set
	if f.path != "" {
		file, err := os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, f.mode)
		if err != nil {
			return nil, err
		}
		f.file = file
	}

	return f, nil
}

func (f *FileOutput) Write(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.file == nil {
		return os.ErrInvalid
	}

	_, err := f.file.Write(b)
	return err
}

func (f *FileOutput) Close() error {
	if f.file != nil {
		return f.file.Close()
	}
	return nil
}

// WithPath sets the file path for the output
func WithPath(path string) func(*FileOutput) {
	return func(f *FileOutput) {
		f.path = path
	}
}

// WithMode sets the file mode for the output
func WithMode(mode os.FileMode) func(*FileOutput) {
	return func(f *FileOutput) {
		f.mode = mode
	}
}
