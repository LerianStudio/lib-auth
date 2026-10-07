package declaration

import (
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wireUnvalidated wires m into auth exactly as WireScope does, without
// validating it first, so the middleware's own guards are what decide.
func wireUnvalidated(m *DeclarationManifest) error {
	return wireManifestScope(&middleware.AuthClient{Logger: obs.Nop()}, m)
}

// The rules both the manifest validation and the middleware enforce must
// refuse the same input in both: a manifest that reaches the middleware some
// other way than WireScope is held to the same rules.
func TestValidationParity_ManifestAndMiddlewareRefuseAlike(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(m *DeclarationManifest)
		// wantManifest and wantMiddleware are the refusals of each entry point.
		wantManifest   string
		wantMiddleware string
	}{
		{
			name: "body_read_as_json_and_form",
			mutate: func(m *DeclarationManifest) {
				m.Scope.Routes[0].Dimensions[1] = DeclarationRouteDimension{Name: "ledgerId", From: "form", Field: "ledger_id"}
			},
			wantManifest:   "scope.routes[0]: reads the request body both as JSON (from: body) and as a form (from: form)",
			wantMiddleware: "reads the request body both as JSON (FromBody) and as a form (FromForm)",
		},
		{
			name: "route_dimension_not_in_catalog",
			mutate: func(m *DeclarationManifest) {
				m.Scope.Routes[0].Dimensions[1] = DeclarationRouteDimension{Name: "accountId", From: "body", Field: "accountId"}
			},
			wantManifest:   `scope.routes[0].dimensions[1]: "accountId" is not a scope dimension of the catalog`,
			wantMiddleware: "dimension accountId on POST /v2/transactions/direct is not declared in the manifest scope of product plugin-fees",
		},
		{
			name: "route_declares_nothing",
			mutate: func(m *DeclarationManifest) {
				m.Scope.Routes[0].Dimensions = nil
			},
			wantManifest:   "scope.routes[0]: must declare at least one dimension",
			wantMiddleware: "POST /v2/transactions/direct declares no dimension",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			valid, err := parseManifest([]byte(routedYAML))
			require.NoError(t, err)
			require.NoError(t, valid.Validate(), "positive control: the manifest is valid before the mutation")
			require.NoError(t, wireUnvalidated(valid), "positive control: the middleware accepts it before the mutation")

			m, err := parseManifest([]byte(routedYAML))
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
