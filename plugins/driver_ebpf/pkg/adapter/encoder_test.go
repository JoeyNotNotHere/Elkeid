package adapter

import (
	"bytes"
	"testing"
)

func TestEncodeVarint(t *testing.T) {
	tests := []struct {
		input  uint64
		output []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x01}},
		{300, []byte{0xac, 0x02}},
	}

	for _, test := range tests {
		res := EncodeVarint(test.input)
		if !bytes.Equal(res, test.output) {
			t.Errorf("EncodeVarint(%d) = %x; want %x", test.input, res, test.output)
		}
	}
}

func TestEncodePacket(t *testing.T) {
	// Simulate execve event (ID 59)
	dataType := 59
	timestamp := int64(1630000000)
	keys := []string{"exe", "pid"}
	values := []string{"/bin/ls", "1234"}

	// Expected structure:
	// Header: Length (4 bytes LE)
	// Payload:
	//   - Varint(59) = 0x3b
	//   - Tag(0x10) + Varint(timestamp)
	//   - Tag(0x1a) + Varint(len) + Map entries

	encoder := NewEncoder()
	packet, err := encoder.EncodePacket(dataType, timestamp, keys, values)
	if err != nil {
		t.Fatalf("EncodePacket failed: %v", err)
	}

	if len(packet) < 4 {
		t.Fatalf("Packet too short: %d", len(packet))
	}

	// Verify Header Length
	// length := binary.LittleEndian.Uint32(packet[:4])
	// t.Logf("Packet Length: %d", length)
}
