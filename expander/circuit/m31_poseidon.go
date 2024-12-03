// Copied and modified from https://github.com/PolyhedraZK/ExpanderCompilerCollection/blob/4398a82/ecgo/examples/poseidon_m31/main.go.

package main

import (
	"fmt"
	"os"

	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/builder"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/field/m31"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/poseidon"
	"github.com/consensys/gnark/frontend"
)

var Param = poseidon.NewPoseidonParams()

type M31PoseidonCircuit struct {
	State  [][16]frontend.Variable
	Digest []frontend.Variable
}

func checkPoseidon(api frontend.API, input []frontend.Variable, output frontend.Variable) {
	digest := poseidon.PoseidonCircuit(api, m31.Field{}, Param, input, true)
	api.AssertIsEqual(digest, output)
}

func (c *M31PoseidonCircuit) Define(api frontend.API) error {
	f := builder.MemorizedVoidFunc(checkPoseidon)
	for i := 0; i < len(c.State); i++ {
		f(api, c.State[i][:], c.Digest[i])
	}
	return nil
}

func NewM31PoseidonCircuit(logPerm int) M31PoseidonCircuit {
	numRepeat := 1 << logPerm
	return M31PoseidonCircuit{
		State:  make([][16]frontend.Variable, numRepeat),
		Digest: make([]frontend.Variable, numRepeat),
	}
}

func main() {
	for _, logPerm := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 15, 16} {
		circuit := NewM31PoseidonCircuit(logPerm)
		result, err := ecgo.Compile(m31.ScalarField, &circuit, frontend.WithCompressThreshold(32))
		if err != nil {
			panic(err)
		}
		layeredCircuit := result.GetLayeredCircuit()
		err = os.WriteFile(fmt.Sprintf("./m31_poseidon/%d.txt", logPerm), layeredCircuit.Serialize(), 0o644)
		if err != nil {
			panic(err)
		}
	}
}
