package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ethereum/go-ethereum/consensus/tendermint/consensus"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/spf13/cobra"
)

var keyDescription *string
var nolock *bool

const (
	ValidatorKeyArmoredBlock = "VALIDATOR PRIVATE KEY"
)

var KeygenCmd = &cobra.Command{
	Use:   "keygen [KEYFILE]",
	Short: "Create validator key at the specified path",
	Run:   runKeygen,
	Args:  cobra.ExactArgs(1),
}

func init() {
	keyDescription = KeygenCmd.Flags().String("desc", "", "Human-readable key description (optional)")
	nolock = KeygenCmd.Flags().Bool("nolock", false, "Do not lock memory (less safer)")
}

func runKeygen(cmd *cobra.Command, args []string) {
	if !*nolock {
		lockMemory()
	} else {
		log.Info("Skipping lockMemory()")
	}
	setRestrictiveUmask()

	log.Info("Creating new key", "location", args[0])

	gk := consensus.GeneratePrivValidatorLocal().(*consensus.PrivValidatorLocal)
	pk, err := gk.GetPubKey(context.Background())
	if err != nil {
		log.Error("Failed to get pub key", "err", err)
		return
	}

	log.Info("Key generated", "address", pk.Address())

	err = writeValidatorKey(gk.PrivKey, *keyDescription, args[0], false)
	if err != nil {
		log.Error("Failed to write key", "err", err)
		return
	}
}

// loadValidatorKey loads a serialized guardian key from disk.
func loadValidatorKey(filename string) (*ecdsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	gk, err := crypto.ToECDSA(b)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize raw key data: %w", err)
	}

	return gk, nil
}

// writeValidatorKey serializes a guardian key and writes it to disk.
func writeValidatorKey(key *ecdsa.PrivateKey, description string, filename string, unsafe bool) error {
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		return errors.New("refusing to override existing key")
	}

	b := crypto.FromECDSA(key)

	err := ioutil.WriteFile(filename, b, 0600)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}
