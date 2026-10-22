package fragment

func tlsRecord(payload []byte) []byte {
	record := make([]byte, 5+len(payload))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x04
	record[3] = byte(len(payload) >> 8)
	record[4] = byte(len(payload))
	copy(record[5:], payload)
	return record
}

func ClientHello(data []byte) ([][]byte, bool) {
	start, end, ok := extractSNIPosition(data)
	if !ok {
		return nil, false
	}

	return sniFragments(data, start, end), true
}

func sniFragments(data []byte, start, end int) [][]byte {
	var parts [][]byte

	if start > 0 {
		parts = append(parts, tlsRecord(data[:start]))
	}

	for i := start; i < end; i += 2 {
		chunkEnd := min(i+2, end)
		parts = append(parts, tlsRecord(data[i:chunkEnd]))
	}

	if end < len(data) {
		parts = append(parts, tlsRecord(data[end:]))
	}

	return parts
}

func extractSNIPosition(data []byte) (start, end int, ok bool) {
	for i := 0; i+9 <= len(data); i++ {
		if data[i] != 0 || data[i+1] != 0 {
			continue
		}

		extensionLength := int(data[i+2])<<8 | int(data[i+3])
		serverNameListLength := int(data[i+4])<<8 | int(data[i+5])

		if data[i+6] != 0 {
			continue
		}

		serverNameLength := int(data[i+7])<<8 | int(data[i+8])

		if extensionLength != serverNameListLength+2 {
			continue
		}
		if serverNameListLength != serverNameLength+3 {
			continue
		}

		start = i + 9
		end = start + serverNameLength
		if serverNameLength == 0 || end > len(data) {
			return 0, 0, false
		}

		return start, end, true
	}

	return 0, 0, false
}
