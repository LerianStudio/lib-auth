package declaration

import (
	"errors"
	"strings"
)

// ScopeCatalog is the catalog an access manager stores for one product: its
// scope dimensions in tree order, its partner opt-in and the level each write
// acts at. Its JSON is the body of the authorization service's catalog write,
// member for member, so every caller that derives a catalog from the same
// manifest writes the same bytes.
type ScopeCatalog struct {
	Product    string                  `json:"product"`
	Dimensions []ScopeCatalogDimension `json:"dimensions"`
	// Partners carries no omitempty: false is a statement, and dropping it would
	// let the receiver default it.
	Partners bool                `json:"partners"`
	Levels   []ScopeCatalogLevel `json:"levels,omitempty"`
	// Integrations are the services the product calls on a request's behalf,
	// trimmed. Omitted when the manifest declares none, which the receiver reads
	// as none.
	Integrations []string `json:"integrations,omitempty"`
}

// ScopeCatalogDimension is one catalog dimension, field for field a
// scope.dimensions entry of the manifest. The booleans carry no omitempty:
// false is a statement. Covers and Parent are omitted when absent, so a
// dimension without them is byte-identical to the shape before they existed.
type ScopeCatalogDimension struct {
	Name       string   `json:"name"`
	From       string   `json:"from"`
	Param      string   `json:"param"`
	Required   bool     `json:"required"`
	Multi      bool     `json:"multi"`
	Collection string   `json:"collection"`
	Covers     []string `json:"covers,omitempty"`
	Label      string   `json:"label"`
	Parent     string   `json:"parent,omitempty"`
}

// ScopeCatalogLevel is how wide one instance of a resource is for one action:
// "tenant", or the name of one of the catalog's dimensions.
type ScopeCatalogLevel struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Level    string `json:"level"`
}

// StoredLevels reads the levels the product's catalog holds right now. It
// returns (nil, nil) when the product has no catalog yet, and an error when the
// catalog cannot be read — which is not the same as "no levels".
type StoredLevels func() ([]ScopeCatalogLevel, error)

// ErrStoredLevelsUnavailable reports that the manifest says nothing about levels,
// so the stored ones have to be kept, and no StoredLevels was given to read them.
var ErrStoredLevelsUnavailable = errors.New("declaration: the manifest declares no levels and the stored ones cannot be read")

// ScopeCatalogFor derives the catalog product's manifest m declares. The bool
// is false when m carries no catalog section — no scope and no partner opt-in —
// and the caller then writes nothing: the catalog it holds stays as it is.
//
// The catalog is replaced wholesale, so the result carries every level it
// should keep:
//
//   - a manifest with an access section (permissions, roles or m2m) is the
//     whole truth about its permissions: the levels are those its permissions
//     declare, and a permission without one contributes none;
//   - a manifest without one says nothing about levels, so the levels the
//     catalog already holds are read through stored and kept. stored is called
//     only then; an error from it is returned and nothing may be written.
//
// Names, sources, params, collections, labels, covers, resources and actions
// are trimmed; the dimension's parent and the level are taken as written, since
// both are compared exactly. scope.routes is not part of the catalog. The
// manifest is not validated here: Validate is the caller's step before it.
func ScopeCatalogFor(m *DeclarationManifest, product string, stored StoredLevels) (ScopeCatalog, bool, error) {
	if m == nil || !m.hasScopeCatalog() {
		return ScopeCatalog{}, false, nil
	}

	var dimensions []DeclarationDimension
	if m.Scope != nil {
		dimensions = m.Scope.Dimensions
	}

	catalog := ScopeCatalog{
		Product:    product,
		Dimensions: make([]ScopeCatalogDimension, 0, len(dimensions)),
		Partners:   m.Partners,

		Integrations: trimmedNames(m.Integrations),
	}

	for _, d := range dimensions {
		catalog.Dimensions = append(catalog.Dimensions, ScopeCatalogDimension{
			Name:       strings.TrimSpace(d.Name),
			From:       strings.TrimSpace(d.From),
			Param:      strings.TrimSpace(d.Param),
			Required:   d.Required,
			Multi:      d.Multi,
			Collection: strings.TrimSpace(d.Collection),
			Covers:     trimmedNames(d.Covers),
			Label:      strings.TrimSpace(d.Label),
			Parent:     d.Parent,
		})
	}

	levels, err := m.catalogLevels(stored)
	if err != nil {
		return ScopeCatalog{}, false, err
	}

	catalog.Levels = levels

	return catalog, true, nil
}

// declaresAccess reports whether the manifest carries the access section:
// permissions, roles or the m2m contract.
func (m *DeclarationManifest) declaresAccess() bool {
	return len(m.Permissions) > 0 || len(m.Roles) > 0 || m.M2M != nil
}

// catalogLevels composes the catalog's levels (see ScopeCatalogFor).
func (m *DeclarationManifest) catalogLevels(stored StoredLevels) ([]ScopeCatalogLevel, error) {
	if m.declaresAccess() {
		var out []ScopeCatalogLevel

		for _, p := range m.Permissions {
			if p.Level == "" {
				continue
			}

			out = append(out, ScopeCatalogLevel{
				Resource: strings.TrimSpace(p.Resource),
				Action:   strings.TrimSpace(p.Action),
				Level:    p.Level,
			})
		}

		return out, nil
	}

	if stored == nil {
		return nil, ErrStoredLevelsUnavailable
	}

	return stored()
}

// trimmedNames returns a list of names (a dimension's covers, the
// integrations) trimmed. Absent stays nil, so the member is omitted for a list
// that names nothing.
func trimmedNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}

	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, strings.TrimSpace(name))
	}

	return out
}
