package cttestsrv

import (
	"context"
	"fmt"

	"github.com/google/trillian"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/compact"
	"github.com/google/trillian/merkle/hashers"
	"github.com/google/trillian/storage/tree"
)

// This code is lifted from Trillian's `server/proof_fetcher.go`:
//   https://github.com/google/trillian/blob/v1.4.0/server/proof_fetcher.go
// It isn't exported in a way that we can use it without implementing
// a TrillianLogRPCServer or using gRPC.
// TODO(@cpu): We should reach out to the upstream and find out if there is
// a better way we could handle this situation.

// nodeReader provides read-only access to the tree nodes.
type nodeReader interface {
	// GetMerkleNodes returns tree nodes by their IDs, in the requested order.
	GetMerkleNodes(ctx context.Context, ids []compact.NodeID) ([]tree.Node, error)
}

func fetchNodesAndBuildProof(ctx context.Context, nr nodeReader, th hashers.LogHasher, leafIndex int64, proofNodeFetches []merkle.NodeFetch) (*trillian.Proof, error) {
	proofNodes, err := fetchNodes(ctx, nr, proofNodeFetches)
	if err != nil {
		return nil, err
	}

	h := make([][]byte, len(proofNodes))
	for i, node := range proofNodes {
		h[i] = node.Hash
	}
	proof, err := merkle.Rehash(h, proofNodeFetches, th.HashChildren)
	if err != nil {
		return nil, err
	}

	return &trillian.Proof{
		LeafIndex: leafIndex,
		Hashes:    proof,
	}, nil
}

// fetchNodes obtains the nodes denoted by the given NodeFetch structs, and
// returns them after some validation checks.
func fetchNodes(ctx context.Context, nr nodeReader, fetches []merkle.NodeFetch) ([]tree.Node, error) {
	ids := make([]compact.NodeID, 0, len(fetches))
	for _, fetch := range fetches {
		ids = append(ids, fetch.ID)
	}

	nodes, err := nr.GetMerkleNodes(ctx, ids)
	if err != nil {
		return nil, err
	}
	if got, want := len(nodes), len(ids); got != want {
		return nil, fmt.Errorf("expected %d nodes from storage but got %d", want, got)
	}
	for i, node := range nodes {
		// Additional check that the correct node was returned.
		if got, want := node.ID, ids[i]; got != want {
			return nil, fmt.Errorf("expected node %v at proof pos %d but got %v", want, i, got)
		}
	}

	return nodes, nil
}
