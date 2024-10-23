package brand

import (
	cryptoRand "crypto/rand"
	"io"
	mathRand "math/rand"
	"time"
)

// brand - balance-random - is a hack, so we can have deterministic random if needed

const needDeterministic = false

// https://github.com/dustin/randbo
type randbo struct {
	mathRand.Source
}

var deterministicReader = New()

func New() io.Reader {
	return NewFrom(mathRand.NewSource(time.Now().UnixNano()))
}

// NewFrom creates a new reader from your own rand.Source
func NewFrom(src mathRand.Source) io.Reader {
	return &randbo{src}
}

// Read satisfies io.Reader
func (r *randbo) Read(p []byte) (n int, err error) {
	todo := len(p)
	offset := 0
	for {
		val := int64(r.Int63())
		for i := 0; i < 8; i++ {
			p[offset] = byte(val)
			todo--
			if todo == 0 {
				return len(p), nil
			}
			offset++
			val >>= 8
		}
	}
}

func Read(b []byte) (n int, err error) {
	if needDeterministic {
		return deterministicReader.Read(b)
	}
	return cryptoRand.Read(b)
}

func Reader() io.Reader {
	if needDeterministic {
		return deterministicReader
	}
	return cryptoRand.Reader
}
