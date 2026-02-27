# Elkeid Driver Protocol Specification (v1)

Derived from `plugins/driver/src/transformer.rs` and `plugins/driver/src/schema.rs`.

## 1. Overview
The protocol uses a custom binary format similar to Protobuf but implemented manually. It supports two modes:
1.  **Binary Mode (Default)**: Custom TLV (Type-Length-Value) encoding with Varints.
2.  **Debug Mode**: JSON encoding (not used for production).

## 2. Binary Structure
A complete message consists of:
1.  **Header**: Length of the payload (4 bytes, Little Endian).
2.  **Payload**:
    *   **Data Type** (Varint): The Event ID (e.g., 59 for execve).
    *   **Timestamp** (Varint + Tag 0x10): Seconds since epoch.
    *   **Body** (Nested TLV + Tag 0x1a): A map of Key-Value pairs.

### 2.1 Encoding Rules

#### Varint
Standard base-128 varint encoding (same as Protobuf).
*   MSB (Most Significant Bit) indicates if more bytes follow.
*   Lower 7 bits hold data.

#### Map Encoding (Body)
The body is a sequence of Key-Value entries encoded as follows:
*   **Total Length** (Varint): Length of the entire map data.
*   **Entries**: Repeated sequence of:
    *   **Entry Length** (Varint): Length of (Key + Value + overhead).
    *   **Tag** (0x0a): Start of Key.
    *   **Key Length** (Varint).
    *   **Key Bytes**.
    *   **Tag** (0x12): Start of Value.
    *   **Value Length** (Varint).
    *   **Value Bytes**.

## 3. Event Schemas (Partial)

### 3.1 Common Fields (Inferred)
Most events seem to share a common prefix of fields:
0.  UID
1.  EXE
2.  ...
3.  PPID
4.  PGID
5.  PID
6.  TID?
10. Namespace?

### 3.2 Specific Events

#### ID 59: `execve`
*   Input Values: 33 fields.
*   **Special Handling**:
    *   Updates `argv_cache` with (PID, ARGV).
    *   Updates `pid_tree_cache`.
    *   Filters: checks `exe_filter` and `argv_filter`.
*   **Enriched Fields**:
    *   [27] `socket_argv` (from cache)
    *   [28] `ppid_argv` (from cache)
    *   [29] `pgid_argv` (from cache)
    *   [30] `username` (from cache)
    *   [31] `pod_name` (from ns_cache)
    *   [32] `exe_hash` (from hash_cache)

#### ID 42: `connect` (socket)
*   Input Values: 25 fields.
*   **Enriched Fields**:
    *   [18] `argv`
    *   [19] `ppid_argv`
    *   [20] `pgid_argv`
    *   [21] `username`
    *   [22] `pod_name`
    *   [23] `exe_hash`
    *   [24] `pid_tree`

## 4. Implementation Plan (Go)

### 4.1 `Encoder` Interface
Needs to implement:
*   `EncodeVarint(n uint64) []byte`
*   `EncodeMap(keys []string, values []string) []byte`
*   `EncodePacket(dataType int, timestamp int64, keys []string, values []string) ([]byte, error)`

### 4.2 `Transformer` Logic
Needs to replicate the caching and enrichment logic:
*   `ArgvCache`: Map[PID] -> ARGV
*   `PidTreeCache`: Map[PID] -> TreeString
*   `NsCache`: Map[NS_ID] -> PodName
