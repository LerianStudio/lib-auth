.PHONY: help build test cover coverage coverage-unit lint format tidy sec setup-git-hooks check-hooks

# Define common utility functions
define print_title
	@echo ""
	@echo "------------------------------------------"
	@echo "   $(1)  "
	@echo "------------------------------------------"
endef

#-------------------------------------------------------
# Help Command
#-------------------------------------------------------

help:
	@echo ""
	@echo "lib-auth Commands"
	@echo ""
	@echo "Core Commands:"
	@echo "  make help              - Display this help message"
	@echo "  make build             - Build and verify compilation"
	@echo "  make test              - Run tests"
	@echo "  make cover             - Run tests with coverage report"
	@echo "  make coverage          - Alias for cover"
	@echo "  make coverage-unit     - Alias for cover"
	@echo ""
	@echo "Code Quality Commands:"
	@echo "  make lint              - Run golangci-lint (auto-installs if missing)"
	@echo "  make format            - Format code with gofmt and goimports"
	@echo "  make tidy              - Clean dependencies (go mod tidy)"
	@echo "  make sec               - Run security checks with gosec"
	@echo ""
	@echo "Git Hook Commands:"
	@echo "  make setup-git-hooks   - Install and configure git hooks"
	@echo "  make check-hooks       - Verify git hooks installation status"
	@echo ""

#-------------------------------------------------------
# Core Commands
#-------------------------------------------------------

build:
	$(call print_title,Building all components)
	@go build ./...
	@echo "[ok] Build completed successfully"

test:
	$(call print_title,Running tests)
	@go test -v ./...
	@echo "[ok] Tests completed successfully"

cover:
	$(call print_title,Generating test coverage report)
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo ""
	@echo "Coverage Summary:"
	@echo "----------------------------------------"
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'
	@echo "----------------------------------------"
	@echo "Open coverage.html in your browser to view detailed coverage report"
	@echo "[ok] Coverage report generated successfully"

coverage: cover

coverage-unit: cover

#-------------------------------------------------------
# Code Quality Commands
#-------------------------------------------------------

lint:
	$(call print_title,Running linter)
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@golangci-lint run ./...
	@echo "[ok] Linting completed successfully"

format:
	$(call print_title,Formatting code)
	@gofmt -s -w .
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	else \
		echo "goimports not found, skipping import organization"; \
		echo "Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi
	@echo "[ok] Formatting completed successfully"

tidy:
	$(call print_title,Cleaning dependencies)
	@go mod tidy
	@echo "[ok] Dependencies cleaned successfully"

sec:
	$(call print_title,Running security checks)
	@if ! command -v gosec >/dev/null 2>&1; then \
		echo "Installing gosec..."; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest; \
	fi
	@gosec ./...
	@echo "[ok] Security checks completed successfully"

#-------------------------------------------------------
# Git Hook Commands
#-------------------------------------------------------

setup-git-hooks:
	$(call print_title,Installing git hooks)
	@for hook in .githooks/*; do \
		hook_name=$$(basename $$hook); \
		cp "$$hook" ".git/hooks/$$hook_name"; \
		chmod +x ".git/hooks/$$hook_name"; \
		echo "Installed $$hook_name"; \
	done
	@echo "[ok] Git hooks installed successfully"

check-hooks:
	$(call print_title,Verifying git hooks installation)
	@err=0; \
	for hook in .githooks/*; do \
		hook_name=$$(basename $$hook); \
		if [ ! -f ".git/hooks/$$hook_name" ]; then \
			echo "Git hook $$hook_name is NOT installed"; \
			err=1; \
		else \
			echo "Git hook $$hook_name is installed"; \
		fi; \
	done; \
	if [ $$err -eq 0 ]; then \
		echo "[ok] All git hooks are properly installed"; \
	else \
		echo "[error] Some git hooks are missing. Run 'make setup-git-hooks' to fix."; \
		exit 1; \
	fi
