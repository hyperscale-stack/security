GO_FILES := $(shell find . -type f -name '*.go' -not -path "./vendor/*")
BUILD_DIR := build

.PHONY: all
all: test

.PHONY: clean
clean:
	@go clean -i ./...

_build:
	@mkdir -p ${BUILD_DIR}

.PHONY: build
build:
	@echo "Building..."
	@go build -race -v ./...

.PHONY: generate
generate:
	@echo "Generating code..."
	@go generate ./...

$(BUILD_DIR)/coverage.out: _build $(GO_FILES)
	@go test -cover -race -coverprofile $(BUILD_DIR)/coverage.out.tmp -timeout 300s ./...
	@cat $(BUILD_DIR)/coverage.out.tmp | grep -v '.pb.go' | grep -v 'mock_' > $(BUILD_DIR)/coverage.out
	@rm $(BUILD_DIR)/coverage.out.tmp

.PHONY: test
test: $(BUILD_DIR)/coverage.out

.PHONY: coverage
coverage: $(BUILD_DIR)/coverage.out
	@echo ""
	@go tool cover -func ./$(BUILD_DIR)/coverage.out

.PHONY: coverage-html
coverage-html: $(BUILD_DIR)/coverage.out
	@go tool cover -html ./$(BUILD_DIR)/coverage.out

.PHONY: bench
bench:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem -benchtime=5s -timeout 300s ./...


.PHONY: lint
lint:
ifeq (, $(shell which golangci-lint))
	@echo "Install golangci-lint..."
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.6.2
endif
	@echo "lint..."
	@golangci-lint run --timeout=300s ./...


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
