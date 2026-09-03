package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/action-state-group/cll-go/ledger"
	gojsonl "github.com/action-state-group/cll-go/store/jsonl"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: go-jsonl <read|write> <root>")
	}
	store, err := gojsonl.Open(os.Args[2], "interop")
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			panic(err)
		}
	}()
	if os.Args[1] == "read" {
		records, err := store.Scan(context.Background(), 0, 10)
		if err != nil {
			panic(err)
		}
		fmt.Printf("records=%d\n", len(records))
		return
	}
	if os.Args[1] != "write" {
		panic("mode must be read or write")
	}
	_, _, err = store.Append(context.Background(), ledger.AppendInput{
		CapsuleID:    ledger.CapsuleID("11" + "11111111111111111111111111111111111111111111111111111111111111"),
		Capsule:      []byte("capsule"),
		Authenticity: ledger.AuthenticityUnsigned,
		AppendedAt:   time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		panic(err)
	}
}
