package adapter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

// Encoder handles the serialization of events into the Elkeid binary protocol.
type Encoder struct{}

// NewEncoder creates a new Encoder instance.
func NewEncoder() *Encoder {
	return &Encoder{}
}

// EncodeVarint encodes a uint64 into a varint byte slice.
// Based on standard base-128 varint encoding.
func EncodeVarint(n uint64) []byte {
	var buf []byte
	for n >= 0x80 {
		buf = append(buf, byte(0x80|(n&0x7f)))
		n >>= 7
	}
	buf = append(buf, byte(n))
	return buf
}

// EncodedVarintLen returns the length of the encoded varint.
func EncodedVarintLen(n uint64) int {
	return len(EncodeVarint(n))
}

// EncodePacket creates a full binary packet for a given event.
// Format: [Total Length (4 bytes LE)] [Payload]
// Payload: [DataType (Varint)] [Timestamp Tag (0x10)] [Timestamp (Varint)] [Body Tag (0x1a)] [Body Length (Varint)] [Body]
func (e *Encoder) EncodePacket(dataType int, timestamp int64, keys []string, values []string) ([]byte, error) {
	if len(keys) != len(values) {
		return nil, errors.New("keys and values length mismatch")
	}

	// 1. Encode Body (Map)
	// We need to iterate and encode each Key-Value pair
	// Note: The Rust implementation iterates 0..len and encodes.
	// It calculates map_length first.

	// Let's construct the map entries first to calculate length.
	// The Rust implementation writes entries in reverse order?
	// Looking at `transformer.rs`:
	// It calculates `needed_length` first.
	// Then it writes from the END of the buffer backwards?
	// "index -= ..."

	// To simplify Go implementation, we can write forward into a buffer and then prepend length.
	// But we must match the wire format.
	// Wire format of a Map Entry seems to be:
	// [Entry Length (Varint)] [0x0a] [Key Len] [Key] [0x12] [Value Len] [Value]
	// And the Map itself is:
	// [Total Map Length (Varint)] [Entry1] [Entry2] ...

	// Wait, checking `transformer.rs` again:
	// entry_length = 1 + key.len + varint(key.len) + 1 + val.len + varint(val.len)
	// map_length += 1 + entry_length + varint(entry_length)
	// The outer 1 is likely the tag for the entry? No, the code says:
	// dst[index] = 0xa; (Tag for Key?)
	// dst[index] = 0x12; (Tag for Value?)
	// dst[index] = 0xa; (Tag for Entry?)

	// Re-reading `transformer.rs`:
	// entry_length includes:
	// - 0x0a (Tag for Key)
	// - Varint(Key Len)
	// - Key Bytes
	// - 0x12 (Tag for Value)
	// - Varint(Value Len)
	// - Value Bytes

	// And the Entry itself is prefixed by:
	// - 0x0a (Tag for Entry, likely field 1 of the map message)
	// - Varint(Entry Length)

	// So the structure is:
	// Map = [0x0a, Len, Entry1] [0x0a, Len, Entry2] ... ?
	// Actually `transformer.rs` loop:
	// for i in 0..keys.len() {
	//    ...
	//    dst[index] = 0xa; // Tag for Entry
	// }
	// So yes, it's a repeated field of Entries.

	// Let's implement writing forward.
	mapBuf := new(bytes.Buffer)
	for i := 0; i < len(keys); i++ {
		key := keys[i]
		val := values[i]

		// Build Entry Payload
		entryPayload := new(bytes.Buffer)

		// Key: Tag 1 (0x0a)
		entryPayload.WriteByte(0x0a)
		entryPayload.Write(EncodeVarint(uint64(len(key))))
		entryPayload.WriteString(key)

		// Value: Tag 2 (0x12)
		entryPayload.WriteByte(0x12)
		entryPayload.Write(EncodeVarint(uint64(len(val))))
		entryPayload.WriteString(val)

		// Write Entry to Map Buffer
		// Entry wrapper: Tag 1 (0x0a) ?? Wait.
		// In `transformer.rs`:
		// dst[index] = 0xa; (This is for the Entry itself?)
		// The `map_length` calculation:
		// map_length += 1 + entry_length + encoded_varint_len(entry_length)
		// So yes, each entry is wrapped as a field (Tag 1).

		mapBuf.WriteByte(0x0a)
		mapBuf.Write(EncodeVarint(uint64(entryPayload.Len())))
		mapBuf.Write(entryPayload.Bytes())
	}

	// 2. Construct Final Payload
	payloadBuf := new(bytes.Buffer)

	// Data Type
	payloadBuf.Write(EncodeVarint(uint64(dataType)))

	// Timestamp: Tag 2 (0x10) -> Varint
	if timestamp != 0 {
		payloadBuf.WriteByte(0x10)
		payloadBuf.Write(EncodeVarint(uint64(timestamp)))
	}

	// Body (Map): Tag 3 (0x1a) -> Bytes
	if mapBuf.Len() > 0 {
		payloadBuf.WriteByte(0x1a)
		payloadBuf.Write(EncodeVarint(uint64(mapBuf.Len())))
		payloadBuf.Write(mapBuf.Bytes())
	}

	// 3. Prepend Header (Total Length)
	// Header is 4 bytes Little Endian.
	// Length = payload length (excluding the header itself).
	// In `transformer.rs`: dst[..4].copy_from_slice(&((needed_length - 4) as u32).to_le_bytes()[..]);

	finalBuf := new(bytes.Buffer)
	length := uint32(payloadBuf.Len())
	binary.Write(finalBuf, binary.LittleEndian, length)
	finalBuf.Write(payloadBuf.Bytes())

	return finalBuf.Bytes(), nil
}

// Encode is a simplified encoding method that uses Schema to get keys.
// It creates a packet with the given event ID and values.
func (e *Encoder) Encode(eventID int, values []string) ([]byte, error) {
	keys := GetSchema(eventID)
	if keys == nil {
		return nil, errors.New("unknown event ID")
	}

	// Ensure values slice matches keys length
	if len(values) < len(keys) {
		// Pad with empty strings
		padded := make([]string, len(keys))
		copy(padded, values)
		values = padded
	} else if len(values) > len(keys) {
		values = values[:len(keys)]
	}

	// Use current timestamp
	timestamp := time.Now().UnixNano()

	return e.EncodePacket(eventID, timestamp, keys, values)
}
