.PHONY: help lint sec

help:
	@echo ""
	@echo "lib-auth Commands"
	@echo "  make help  - Display this help message"
	@echo "  make lint  - Run golangci-lint over ./... (auto-installs if missing)"
	@echo "  make sec   - Run gosec over ./... (auto-installs if missing)"

lint:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	golangci-lint run ./...

sec:
	@if ! command -v gosec >/dev/null 2>&1; then \
		echo "Installing gosec..."; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest; \
	fi
	gosec ./...


