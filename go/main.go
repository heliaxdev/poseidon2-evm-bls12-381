package main

import (
	"os"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
)

func main() {
	hasher := poseidon2.NewPermutation(2, 8, 56)

	var left, right fr.Element
	_, err := left.SetString(os.Args[1])
	if err != nil {
		panic(err)
	}
	_, err = right.SetString(os.Args[2])
	if err != nil {
		panic(err)
	}

	state := []fr.Element{left, right}
	hasher.Permutation(state)

	var result fr.Element
	result.Add(&state[1], &right) // feed-forward step

	fmt.Printf("Compress Result: %s\n", result.String())
}
