package declaration

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scopeCatalogVector is one entry of testdata/scope_catalog_vectors.json: a
// manifest, the levels the catalog holds before the write (absent: no catalog),
// and the catalog the access manager writes for it, byte for byte.
type scopeCatalogVector struct {
	Name         string               `json:"name"`
	Product      string               `json:"product"`
	Manifest     string               `json:"manifest"`
	ManifestFile string               `json:"manifestFile"`
	Stored       *[]ScopeCatalogLevel `json:"stored"`
	Declares     bool                 `json:"declares"`
	ReadsStored  bool                 `json:"readsStored"`
	Catalog      json.RawMessage      `json:"catalog"`
}

func loadScopeCatalogVectors(t *testing.T) []scopeCatalogVector {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "scope_catalog_vectors.json"))
	require.NoError(t, err)

	var vectors []scopeCatalogVector
	require.NoError(t, json.Unmarshal(raw, &vectors))
	require.NotEmpty(t, vectors)

	return vectors
}

func (v scopeCatalogVector) manifest(t *testing.T) *DeclarationManifest {
	t.Helper()

	src := []byte(v.Manifest)

	if v.ManifestFile != "" {
		var err error

		src, err = os.ReadFile(filepath.Join("testdata", v.ManifestFile))
		require.NoError(t, err)
	}

	m, err := parseManifest(src)
	require.NoError(t, err)
	require.NoError(t, m.Validate(), "a vector is a manifest a product can publish")

	return m
}

func TestScopeCatalogFor_MatchesTheVectors(t *testing.T) {
	t.Parallel()

	for _, v := range loadScopeCatalogVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()

			reads := 0
			stored := func() ([]ScopeCatalogLevel, error) {
				reads++

				if v.Stored == nil {
					return nil, nil
				}

				return *v.Stored, nil
			}

			catalog, declares, err := ScopeCatalogFor(v.manifest(t), v.Product, stored)
			require.NoError(t, err)

			assert.Equal(t, v.Declares, declares)
			assert.Equal(t, v.ReadsStored, reads > 0, "the stored levels are read only when the manifest says nothing about them")

			if !v.Declares {
				assert.Equal(t, "null", string(v.Catalog))

				return
			}

			var want bytes.Buffer
			require.NoError(t, json.Compact(&want, v.Catalog))

			got, err := json.Marshal(catalog)
			require.NoError(t, err)

			assert.Equal(t, want.String(), string(got))
		})
	}
}

func TestScopeCatalogFor_NoManifestDeclaresNothing(t *testing.T) {
	t.Parallel()

	catalog, declares, err := ScopeCatalogFor(nil, "midaz", nil)

	require.NoError(t, err)
	assert.False(t, declares)
	assert.Equal(t, ScopeCatalog{}, catalog)
}

// A catalog that cannot be read is not "no levels": nothing may be written.
func TestScopeCatalogFor_AnUnreadableStoredCatalogIsAnError(t *testing.T) {
	t.Parallel()

	down := errors.New("provider down")

	_, declares, err := ScopeCatalogFor(&DeclarationManifest{Service: "midaz", Partners: true}, "midaz",
		func() ([]ScopeCatalogLevel, error) { return nil, down })

	require.ErrorIs(t, err, down)
	assert.False(t, declares)
}

// Without a reader the stored levels cannot be kept, so the write is refused
// rather than clearing them.
func TestScopeCatalogFor_KeepingLevelsNeedsAReader(t *testing.T) {
	t.Parallel()

	_, declares, err := ScopeCatalogFor(&DeclarationManifest{Service: "midaz", Partners: true}, "midaz", nil)

	require.ErrorIs(t, err, ErrStoredLevelsUnavailable)
	assert.False(t, declares)

	// A manifest that states its levels needs none.
	_, declares, err = ScopeCatalogFor(&DeclarationManifest{
		Service:     "midaz",
		Partners:    true,
		Permissions: []DeclarationPermission{{Resource: "ledgers", Action: "post", Effect: effectAllow, Roles: []string{"editor"}}},
		Roles:       []DeclarationRole{{Name: "editor"}},
	}, "midaz", nil)

	require.NoError(t, err)
	assert.True(t, declares)
}
