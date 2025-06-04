APP_NAME = innocent
BIN_DIR = bin
VERSION = $(shell git describe --tags --always --dirty)

# Supported platforms and architectures
PLATFORMS = \
	linux/amd64 \
	linux/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: all clean build build-all

all: build-all

# Build for current system
build:
	@echo "Building for current system..."
	GOOS=$(shell go env GOOS) GOARCH=$(shell go env GOARCH) \
		go build -ldflags="-X main.version=$(VERSION)" -o $(BIN_DIR)/$(APP_NAME) main.go
	@echo "Built: $(BIN_DIR)/$(APP_NAME)"

# Build for all specified platforms
build-all:
	@echo "Building for all target platforms..."
	@mkdir -p $(BIN_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*}; \
		GOARCH=$${platform#*/}; \
		output_name=$(APP_NAME)-$${GOOS}-$${GOARCH}; \
		[ "$$GOOS" = "windows" ] && output_name=$$output_name.exe; \
		echo " -> $$GOOS/$$GOARCH"; \
		GOOS=$$GOOS GOARCH=$$GOARCH CGO_ENABLED=0 \
			go build -ldflags="-X main.version=$(VERSION)" -o $(BIN_DIR)/$$output_name main.go || echo "Failed to build for $$platform"; \
	done
	@echo "All builds complete."

# Clean build output
clean:
	@echo "Cleaning..."
	rm -rf $(BIN_DIR)
	@echo "Done."