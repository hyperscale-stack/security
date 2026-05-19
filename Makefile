BUILD_DIR := build
LINT_CONFIG := $(CURDIR)/.golangci.yml

# All Go modules in the workspace, derived from go.work to stay in sync.
# Note: the leading "./" is required for find -execdir / cd targets.
MODULES := $(shell find . -name go.mod -not -path '*/vendor/*' -not -path '*/node_modules/*' -not -path '*/build/*' | sort | sed 's|/go.mod||')

.PHONY: all
all: test

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)
	@for mod in $(MODULES); do (cd "$$mod" && go clean -i ./...); done

_build:
	@mkdir -p $(BUILD_DIR)

.PHONY: sync
sync:
	@echo "Syncing workspace..."
	@go work sync

.PHONY: build
build:
	@for mod in $(MODULES); do \
		echo "==> build $$mod"; \
		(cd "$$mod" && go build -v ./...) || exit 1; \
	done

.PHONY: generate
generate:
	@echo "Generating mocks..."
	@go generate ./...

.PHONY: test
test: _build
	@: > $(BUILD_DIR)/coverage.out
	@for mod in $(MODULES); do \
		echo "==> test $$mod"; \
		mod_safe=$$(echo "$$mod" | sed 's|/|_|g; s|^\._||; s|^\.$$|root|'); \
		(cd "$$mod" && go test -cover -race \
			-coverprofile="$(CURDIR)/$(BUILD_DIR)/$$mod_safe.cover" \
			-timeout 300s ./...) || exit 1; \
	done
	@grep -h -v '^mode:' $(BUILD_DIR)/*.cover 2>/dev/null \
		| grep -v 'mock_' | grep -v '.pb.go' \
		> $(BUILD_DIR)/coverage.body || true
	@echo 'mode: atomic' > $(BUILD_DIR)/coverage.out
	@cat $(BUILD_DIR)/coverage.body >> $(BUILD_DIR)/coverage.out
	@rm -f $(BUILD_DIR)/*.cover $(BUILD_DIR)/coverage.body

.PHONY: coverage
coverage: $(BUILD_DIR)/coverage.out
	@go tool cover -func ./$(BUILD_DIR)/coverage.out

.PHONY: coverage-html
coverage-html: $(BUILD_DIR)/coverage.out
	@go tool cover -html ./$(BUILD_DIR)/coverage.out

.PHONY: bench
bench:
	@for mod in $(MODULES); do \
		echo "==> bench $$mod"; \
		(cd "$$mod" && go test -bench=. -benchmem -benchtime=5s -timeout 300s ./...) || exit 1; \
	done

.PHONY: lint
lint:
ifeq (, $(shell which golangci-lint))
	@echo "Install golangci-lint..."
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
		| sh -s -- -b $$(go env GOPATH)/bin v2.6.2
endif
	@for mod in $(MODULES); do \
		echo "==> lint $$mod"; \
		(cd "$$mod" && golangci-lint run --timeout=300s --config="$(LINT_CONFIG)" ./...) || exit 1; \
	done

.PHONY: tidy
tidy:
	@for mod in $(MODULES); do \
		echo "==> tidy $$mod"; \
		(cd "$$mod" && go mod tidy) || exit 1; \
	done
	@go work sync

.PHONY: release
release:
	@echo "Release v$(version)"
	@git pull
	@git checkout master
	@git pull
	@git checkout develop
	@git flow release start $(version)
	@git flow release finish $(version) -p -m "Release v$(version)"
	@git checkout develop
	@echo "Release v$(version) finished."
