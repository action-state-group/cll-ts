package main

import (
	"fmt"
	"os"
	"time"

	"github.com/ethanyzhang/capsule-ledger-go/checkpoint"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		panic("usage: go-checkpoint <checkpoint.cose> [expected-rfc3339nano]")
	}
	statement, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	record, err := checkpoint.ParseRecord(statement)
	if err != nil {
		panic(err)
	}
	if err := record.VerifySignature(); err != nil {
		panic(err)
	}
	timestamp := record.Timestamp.UTC().Format(time.RFC3339Nano)
	if len(os.Args) == 3 && timestamp != os.Args[2] {
		panic(fmt.Sprintf("timestamp = %q, want %q", timestamp, os.Args[2]))
	}
	fmt.Printf("log_id=%s mmr_size=%d timestamp=%s\n", record.LogID, record.MMRSize, timestamp)
}
