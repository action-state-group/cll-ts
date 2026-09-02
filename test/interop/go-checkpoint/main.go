package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/ethanyzhang/cll-go/checkpoint"
	"github.com/ethanyzhang/cll-go/mmr"
)

const timestamp = "2026-08-27T12:34:56Z"

func main() {
	if len(os.Args) != 3 {
		panic("usage: go-checkpoint <write|verify> <checkpoint.cose>")
	}
	var err error
	switch os.Args[1] {
	case "write":
		err = writeCheckpoint(os.Args[2])
	case "verify":
		err = verifyCheckpoint(os.Args[2])
	default:
		err = fmt.Errorf("mode must be write or verify")
	}
	if err != nil {
		panic(err)
	}
}

func writeCheckpoint(path string) error {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	signer, err := checkpoint.NewEd25519Signer(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return err
	}
	tree, err := mmr.New(nil)
	if err != nil {
		return err
	}
	if _, err := tree.Append(bytes.Repeat([]byte{0x11}, 32)); err != nil {
		return err
	}
	root, err := tree.Root()
	if err != nil {
		return err
	}
	peaks, err := tree.PeakHashesAt(tree.Size())
	if err != nil {
		return err
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return err
	}
	payload, err := (checkpoint.Payload{
		LogID:     "interop-log",
		KeyID:     signer.KeyID(),
		MMRSize:   tree.Size(),
		Root:      hex.EncodeToString(root),
		Timestamp: issuedAt,
	}).CanonicalJSON()
	if err != nil {
		return err
	}
	statement, err := signer.SignCheckpoint(context.Background(), payload, peaks, nil, nil)
	if err != nil {
		return err
	}
	return os.WriteFile(path, statement, 0o600)
}

func verifyCheckpoint(path string) error {
	statement, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	record, err := checkpoint.ParseRecord(statement)
	if err != nil {
		return err
	}
	if err := record.VerifySignature(); err != nil {
		return err
	}
	if actual := record.Timestamp.UTC().Format(time.RFC3339Nano); actual != timestamp {
		return fmt.Errorf("timestamp = %q, want %q", actual, timestamp)
	}
	fmt.Printf("log_id=%s mmr_size=%d timestamp=%s\n", record.LogID, record.MMRSize, timestamp)
	return nil
}
