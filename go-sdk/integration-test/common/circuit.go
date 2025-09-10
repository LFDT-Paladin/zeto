package common

import (
	"fmt"
	"os"
	"path"

	"github.com/iden3/go-rapidsnark/witness/v2"
	"github.com/iden3/go-rapidsnark/witness/wasmer"
)

func LoadCircuit(circuitName string) (witness.Calculator, []byte, error) {
	circuitRoot, exists := os.LookupEnv("CIRCUITS_ROOT")
	if !exists {
		return nil, []byte{}, fmt.Errorf("CIRCUITS_ROOT not set")
	}
	provingKeysRoot, exists := os.LookupEnv("PROVING_KEYS_ROOT")
	if !exists {
		return nil, []byte{}, fmt.Errorf("PROVING_KEYS_ROOT not set")
	}

	// load the wasm file for the circuit
	wasmBytes, err := os.ReadFile(path.Join(circuitRoot, fmt.Sprintf("%s_js", circuitName), fmt.Sprintf("%s.wasm", circuitName)))
	if err != nil {
		return nil, []byte{}, err
	}

	// create the prover
	zkeyBytes, err := os.ReadFile(path.Join(provingKeysRoot, fmt.Sprintf("%s.zkey", circuitName)))
	if err != nil {
		return nil, []byte{}, err
	}

	// create the calculator
	var ops []witness.Option
	ops = append(ops, witness.WithWasmEngine(wasmer.NewCircom2WitnessCalculator))
	calc, err := witness.NewCalculator(wasmBytes, ops...)
	if err != nil {
		return nil, []byte{}, err
	}

	return calc, zkeyBytes, err
}
