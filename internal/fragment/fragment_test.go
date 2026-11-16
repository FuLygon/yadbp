package fragment

import (
	"bytes"
	"testing"
)

func TestIsClientHello(t *testing.T) {
	tests := []struct {
		name   string
		record []byte
		want   bool
	}{
		{
			name:   "client hello",
			record: []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00},
			want:   true,
		},
		{
			name:   "application data",
			record: []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00},
			want:   false,
		},
		{
			name:   "handshake is not client hello",
			record: []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
			want:   false,
		},
		{
			name:   "exactly five bytes",
			record: []byte{0x16, 0x03, 0x03, 0x00, 0x00},
			want:   false,
		},
		{
			name:   "empty",
			record: nil,
			want:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsClientHello(test.record); got != test.want {
				t.Fatalf("IsClientHello() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestTCPChunks(t *testing.T) {
	t.Run("empty record", func(t *testing.T) {
		if chunks := TCPChunks(nil); chunks != nil {
			t.Fatalf("TCPChunks(nil) = %#v, want nil", chunks)
		}
	})

	tests := []struct {
		name       string
		size       int
		wantChunks int
	}{
		{name: "shorter than one chunk", size: TCPChunkSize - 1, wantChunks: 1},
		{name: "exactly one chunk", size: TCPChunkSize, wantChunks: 1},
		{name: "one full and one partial", size: TCPChunkSize + 1, wantChunks: 2},
		{name: "two full chunks", size: TCPChunkSize * 2, wantChunks: 2},
		{name: "two full and one partial", size: TCPChunkSize*2 + 3, wantChunks: 3},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := make([]byte, test.size)
			for i := range record {
				record[i] = byte(i % 251)
			}

			chunks := TCPChunks(record)
			if len(chunks) != test.wantChunks {
				t.Fatalf("len(TCPChunks()) = %d, want %d", len(chunks), test.wantChunks)
			}

			var reassembled []byte
			for i, chunk := range chunks {
				if len(chunk) == 0 || len(chunk) > TCPChunkSize {
					t.Fatalf("chunk %d has length %d, want 1..%d", i, len(chunk), TCPChunkSize)
				}
				if i < len(chunks)-1 && len(chunk) != TCPChunkSize {
					t.Fatalf("chunk %d has length %d, want %d", i, len(chunk), TCPChunkSize)
				}
				reassembled = append(reassembled, chunk...)
			}

			if !bytes.Equal(reassembled, record) {
				t.Fatal("chunks do not reassemble to the original record")
			}
		})
	}
}

func TestTCPChunksShareBackingArray(t *testing.T) {
	record := make([]byte, TCPChunkSize+1)
	chunks := TCPChunks(record)

	if len(chunks) != 2 {
		t.Fatalf("len(TCPChunks()) = %d, want 2", len(chunks))
	}
	if &chunks[0][0] != &record[0] {
		t.Fatal("first chunk does not alias the start of record")
	}
	if &chunks[1][0] != &record[TCPChunkSize] {
		t.Fatal("second chunk does not alias the second segment of record")
	}
}
