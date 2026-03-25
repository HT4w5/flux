package output

import (
	"time"

	"github.com/HT4w5/flux/pkg/output/stdout"
	"github.com/valyala/bytebufferpool"
)

type OutputDriver interface {
	// Must be thread-safe
	Write(b []byte) error
	Close() error
}

// Prints flagged targets for fail2ban
type Output struct {
	driver OutputDriver
}

func New(opts ...func(*Output)) *Output {
	o := &Output{
		driver: &stdout.StdoutOutput{},
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

func WithDriver(driver OutputDriver) func(*Output) {
	return func(o *Output) {
		o.driver = driver
	}
}

func (o *Output) BeginTx() *Tx {
	return &Tx{
		output: o,
		bbuf:   bytebufferpool.Get(),
	}
}

func (o *Output) Close() error {
	return o.driver.Close()
}

type Tx struct {
	invalid bool
	output  *Output
	bbuf    *bytebufferpool.ByteBuffer
}

func (tx *Tx) Add(entry OutputEntry) {
	tx.bbuf.WriteString(entry.Time.Format(time.RFC3339))
	tx.bbuf.WriteByte(' ')
	tx.bbuf.WriteString(entry.Tag)
	tx.bbuf.WriteByte(' ')
	tx.bbuf.WriteString(entry.Host.String())
	tx.bbuf.WriteByte(' ')
	tx.bbuf.WriteString(entry.Blame)
	tx.bbuf.WriteByte('\n')
}

func (tx *Tx) Commit() error {
	if tx.invalid {
		return nil
	}
	tx.invalid = true
	defer bytebufferpool.Put(tx.bbuf)
	return tx.output.driver.Write(tx.bbuf.Bytes())
}

func (tx *Tx) Rollback() {
	if tx.invalid {
		return
	}
	tx.invalid = true
	bytebufferpool.Put(tx.bbuf)
}
