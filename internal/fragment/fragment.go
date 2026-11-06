package fragment

// TCPChunkSize is the number of bytes written per TCP segment. Splitting the
// ClientHello into small writes keeps the SNI hostname from appearing in a
// single segment while leaving the TLS record itself untouched.
const TCPChunkSize = 40

// IsClientHello reports whether record starts with a TLS handshake record that
// carries a ClientHello. Other CONNECT payloads (SSH, plain sockets) must pass
// through untouched.
func IsClientHello(record []byte) bool {
	return len(record) > 5 && record[0] == 0x16 && record[5] == 0x01
}

// TCPChunks splits record into TCPChunkSize-byte pieces. The pieces are slices
// of record and reassemble to the original bytes, so the TLS record remains
// valid.
func TCPChunks(record []byte) [][]byte {
	if len(record) == 0 {
		return nil
	}

	chunks := make([][]byte, 0, (len(record)+TCPChunkSize-1)/TCPChunkSize)
	for offset := 0; offset < len(record); offset += TCPChunkSize {
		end := offset + TCPChunkSize
		if end > len(record) {
			end = len(record)
		}
		chunks = append(chunks, record[offset:end])
	}
	return chunks
}
