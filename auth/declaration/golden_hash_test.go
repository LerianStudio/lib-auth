package declaration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// canonicalHashCoversGolden is the CanonicalHash of testdata/canonical_hash_covers.json
// as the authorization service computes it for the same bytes. The publisher
// skips a PUT whose hash it already published, so a client hash that drifts from
// the service's for the same manifest re-publishes forever or, worse, never
// publishes a change. The literal is the contract: it is not recomputed here.
const canonicalHashCoversGolden = "7f93c886cc377898097aae284416289111764c5039ce85e1872cdc57f0b91624"

func TestCanonicalHash_GoldenWithCovers(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "canonical_hash_covers.json"))
	require.NoError(t, err)

	m, err := parseManifest(raw)
	require.NoError(t, err)
	require.NoError(t, m.Validate())
	require.Equal(t, []string{"balances", "operations"}, m.Scope.Dimensions[1].Covers,
		"the fixture must carry covers, or the golden proves nothing about them")

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, canonicalHashCoversGolden, hash)
}
