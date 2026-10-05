package declaration

import (
	"context"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wireUnvalidated wires m into auth exactly as WireScope does, without
// validating it first, so the middleware's own guards are what decide.
func wireUnvalidated(m *DeclarationManifest) error {
	auth := &middleware.AuthClient{Logger: obs.Nop()}

	resolve := func(context.Context, middleware.ResolveInput) ([][]string, error) { return nil, nil }
	for _, name := range []string{"alias", "holderLedgers"} {
		if err := auth.RegisterScopeResolver(name, resolve); err != nil {
			return err
		}
	}

	if err := auth.SetManifestScope(m.Service, catalogDimensions(m.Scope)...); err != nil {
		return err
	}

	for _, r := range m.Scope.Routes {
		if err := wireRoute(auth, m.Service, r); err != nil {
			return err
		}
	}

	return nil
}

// The rules both the manifest validation and the middleware enforce must
// refuse the same input in both: a manifest that reaches the middleware some
// other way than WireScope is held to the same rules.
func TestValidationParity_ManifestAndMiddlewareRefuseAlike(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		manifest string
		mutate   func(m *DeclarationManifest)
		// wantManifest and wantMiddleware are the refusals of each entry point.
		wantManifest   string
		wantMiddleware string
	}{
		{
			name:           "filter_empty_entry",
			manifest:       filteredYAML,
			mutate:         func(m *DeclarationManifest) { m.Scope.Routes[0].Filter = []string{""} },
			wantManifest:   "scope.routes[0].filter[0]: must not be empty",
			wantMiddleware: "filters on a dimension with no name",
		},
		{
			name:           "filter_duplicate",
			manifest:       filteredYAML,
			mutate:         func(m *DeclarationManifest) { m.Scope.Routes[0].Filter = []string{"accountId", "accountId"} },
			wantManifest:   `scope.routes[0].filter[1]: duplicate dimension "accountId"`,
			wantMiddleware: "filters on dimension accountId more than once",
		},
		{
			name:           "catalog_match_without_resolve",
			manifest:       matchYAML,
			mutate:         func(m *DeclarationManifest) { m.Scope.Dimensions[2].Resolve = "" },
			wantManifest:   "scope.dimensions[2]: match requires resolve",
			wantMiddleware: "scope dimension accountId matches any of its resolved values but names no resolver",
		},
		{
			name:     "route_match_without_resolve",
			manifest: matchYAML,
			mutate: func(m *DeclarationManifest) {
				m.Scope.Routes[0].Dimensions[0] = DeclarationRouteDimension{Name: "accountId", From: "query", Field: "account", Match: "any"}
			},
			wantManifest:   "scope.routes[0].dimensions[0]: match requires resolve",
			wantMiddleware: "scope dimension accountId matches any of its resolved values but names no resolver",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			valid, err := parseManifest([]byte(tt.manifest))
			require.NoError(t, err)
			require.NoError(t, valid.Validate(), "positive control: the manifest is valid before the mutation")
			require.NoError(t, wireUnvalidated(valid), "positive control: the middleware accepts it before the mutation")

			m, err := parseManifest([]byte(tt.manifest))
			require.NoError(t, err)
			tt.mutate(m)

			err = m.Validate()
			require.Error(t, err, "the manifest validation must refuse it")
			assert.Contains(t, err.Error(), tt.wantManifest)

			err = wireUnvalidated(m)
			require.Error(t, err, "the middleware must refuse it")
			assert.Contains(t, err.Error(), tt.wantMiddleware)
		})
	}
}
