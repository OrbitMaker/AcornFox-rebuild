package install

import (
	"bytes"
	"compress/gzip"
	"io"
	"math/rand"
	"testing"
)

type countedArchiveInput struct {
	io.Reader
	reads int
}

func (r *countedArchiveInput) Read(b []byte) (int, error) { r.reads++; return r.Reader.Read(b) }

func TestAcornFoxArchiveDoesNotReadFileForEveryCompressedByte(t *testing.T) {
	data := make([]byte, 512<<10)
	_, _ = rand.New(rand.NewSource(71)).Read(data)
	for i := range data {
		data[i] &= 15
	} // force compressed Huffman blocks, not stored blocks
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	_, _ = w.Write(data)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw := compressed.Bytes()
	for _, tc := range []struct {
		name   string
		body   []byte
		size   int64
		accept bool
	}{
		{"exact", raw, int64(len(raw)), true},
		{"undeclared trailer", append(append([]byte{}, raw...), 1), int64(len(raw)), false},
		{"declared trailer", append(append([]byte{}, raw...), 1), int64(len(raw) + 1), false},
		{"second gzip member", append(append([]byte{}, raw...), raw...), int64(2 * len(raw)), false},
		{"short declaration", raw, int64(len(raw) - 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := &countedArchiveInput{Reader: bytes.NewReader(tc.body)}
			stream, err := newAcornFoxExactArchiveReader(input, tc.size)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := gzip.NewReader(stream)
			if err != nil {
				t.Fatal(err)
			}
			reader.Multistream(false)
			decoded, readErr := io.ReadAll(reader)
			closeErr := reader.Close()
			finishErr := stream.finish(sha256Hex(raw))
			passed := readErr == nil && closeErr == nil && finishErr == nil && bytes.Equal(decoded, data)
			if passed != tc.accept {
				t.Fatalf("accept=%v read=%v close=%v finish=%v", passed, readErr, closeErr, finishErr)
			}
			if input.reads > 4096 {
				t.Fatalf("%d underlying reads for a 512 KiB archive; per-byte file I/O remains", input.reads)
			}
		})
	}
}
