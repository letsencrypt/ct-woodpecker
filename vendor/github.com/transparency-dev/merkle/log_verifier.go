// Copyright 2017 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package merkle

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
)

// RootMismatchError occurs when an inclusion proof fails.
type RootMismatchError struct {
	ExpectedRoot   []byte
	CalculatedRoot []byte
}

func (e RootMismatchError) Error() string {
	return fmt.Sprintf("calculated root:\n%v\n does not match expected root:\n%v", e.CalculatedRoot, e.ExpectedRoot)
}

// LogHasher provides the hash functions needed to compute dense merkle trees.
type LogHasher interface {
	// EmptyRoot supports returning a special case for the root of an empty tree.
	EmptyRoot() []byte
	// HashLeaf computes the hash of a leaf that exists.
	HashLeaf(leaf []byte) []byte
	// HashChildren computes interior nodes.
	HashChildren(l, r []byte) []byte
	// Size returns the number of bytes the Hash* functions will return.
	Size() int
}

// LogVerifier verifies inclusion and consistency proofs for append only logs.
type LogVerifier struct {
	hasher LogHasher
}

// NewLogVerifier returns a new LogVerifier for a tree.
func NewLogVerifier(hasher LogHasher) LogVerifier {
	return LogVerifier{hasher}
}

// VerifyInclusion verifies the correctness of the inclusion proof for the leaf
// with the specified hash and index, relatively to the tree of the given size
// and root hash. Requires 0 <= index < size.
func (v LogVerifier) VerifyInclusion(index, size uint64, leafHash []byte, proof [][]byte, root []byte) error {
	calcRoot, err := v.RootFromInclusionProof(index, size, leafHash, proof)
	if err != nil {
		return err
	}
	if !bytes.Equal(calcRoot, root) {
		return RootMismatchError{
			CalculatedRoot: calcRoot,
			ExpectedRoot:   root,
		}
	}
	return nil
}

// RootFromInclusionProof calculates the expected root hash for a tree of the
// given size, provided a leaf index and hash with the corresponding inclusion
// proof. Requires 0 <= index < size.
func (v LogVerifier) RootFromInclusionProof(index, size uint64, leafHash []byte, proof [][]byte) ([]byte, error) {
	if index >= size {
		return nil, fmt.Errorf("index is beyond size: %d >= %d", index, size)
	}
	if got, want := len(leafHash), v.hasher.Size(); got != want {
		return nil, fmt.Errorf("leafHash has unexpected size %d, want %d", got, want)
	}

	inner, border := decompInclProof(index, size)
	if got, want := len(proof), inner+border; got != want {
		return nil, fmt.Errorf("wrong proof size %d, want %d", got, want)
	}

	ch := hashChainer(v)
	res := ch.chainInner(leafHash, proof[:inner], index)
	res = ch.chainBorderRight(res, proof[inner:])
	return res, nil
}

// VerifyConsistency checks that the passed-in consistency proof is valid
// between the passed in tree sizes, with respect to the corresponding root
// hashes. Requires 0 <= size1 <= size2.
func (v LogVerifier) VerifyConsistency(size1, size2 uint64, root1, root2 []byte, proof [][]byte) error {
	switch {
	case size2 < size1:
		return fmt.Errorf("size2 (%d) < size1 (%d)", size1, size2)
	case size1 == size2:
		if !bytes.Equal(root1, root2) {
			return RootMismatchError{
				CalculatedRoot: root1,
				ExpectedRoot:   root2,
			}
		} else if len(proof) > 0 {
			return errors.New("root1 and root2 match, but proof is non-empty")
		}
		return nil // Proof OK.
	case size1 == 0:
		// Any size greater than 0 is consistent with size 0.
		if len(proof) > 0 {
			return fmt.Errorf("expected empty proof, but got %d components", len(proof))
		}
		return nil // Proof OK.
	case len(proof) == 0:
		return errors.New("empty proof")
	}

	inner, border := decompInclProof(size1-1, size2)
	shift := bits.TrailingZeros64(size1)
	inner -= shift // Note: shift < inner if size1 < size2.

	// The proof includes the root hash for the sub-tree of size 2^shift.
	seed, start := proof[0], 1
	if size1 == 1<<uint(shift) { // Unless size1 is that very 2^shift.
		seed, start = root1, 0
	}
	if got, want := len(proof), start+inner+border; got != want {
		return fmt.Errorf("wrong proof size %d, want %d", got, want)
	}
	proof = proof[start:]
	// Now len(proof) == inner+border, and proof is effectively a suffix of
	// inclusion proof for entry |size1-1| in a tree of size |size2|.

	// Verify the first root.
	ch := hashChainer(v)
	mask := (size1 - 1) >> uint(shift) // Start chaining from level |shift|.
	hash1 := ch.chainInnerRight(seed, proof[:inner], mask)
	hash1 = ch.chainBorderRight(hash1, proof[inner:])
	if !bytes.Equal(hash1, root1) {
		return RootMismatchError{
			CalculatedRoot: hash1,
			ExpectedRoot:   root1,
		}
	}

	// Verify the second root.
	hash2 := ch.chainInner(seed, proof[:inner], mask)
	hash2 = ch.chainBorderRight(hash2, proof[inner:])
	if !bytes.Equal(hash2, root2) {
		return RootMismatchError{
			CalculatedRoot: hash2,
			ExpectedRoot:   root2,
		}
	}

	return nil // Proof OK.
}

// decompInclProof breaks down inclusion proof for a leaf at the specified
// |index| in a tree of the specified |size| into 2 components. The splitting
// point between them is where paths to leaves |index| and |size-1| diverge.
// Returns lengths of the bottom and upper proof parts correspondingly. The sum
// of the two determines the correct length of the inclusion proof.
func decompInclProof(index, size uint64) (int, int) {
	inner := innerProofSize(index, size)
	border := bits.OnesCount64(index >> uint(inner))
	return inner, border
}

func innerProofSize(index, size uint64) int {
	return bits.Len64(index ^ (size - 1))
}
