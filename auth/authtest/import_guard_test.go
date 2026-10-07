package authtest_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authtestImportPath is the package that must never reach production wiring.
const authtestImportPath = "github.com/LerianStudio/lib-auth/v5/auth/authtest"

// TestAuthtest_IsImportedOnlyByTests walks every non-test .go file in the
// module and fails if any of them, outside auth/authtest itself, imports
// auth/authtest. A principal placed on a context without a token is a
// production bypass; this guard keeps lib-auth from shipping one. Consumers
// apply the same rule with the depguard entry in the README.
func TestAuthtest_IsImportedOnlyByTests(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)

	self := filepath.Join(root, "auth", "authtest")

	var offenders []string

	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() {
			if path == self || strings.HasPrefix(entry.Name(), ".") && path != root {
				return filepath.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}

		for _, imp := range file.Imports {
			importPath, unquoteErr := strconv.Unquote(imp.Path.Value)
			if unquoteErr != nil {
				return unquoteErr
			}

			if importPath == authtestImportPath {
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					return relErr
				}

				offenders = append(offenders, filepath.ToSlash(rel))
			}
		}

		return nil
	})
	require.NoError(t, err)

	assert.Empty(t, offenders, "auth/authtest is test-only; production code must never import it")
}
