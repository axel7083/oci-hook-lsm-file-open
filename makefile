# ---- Configuration ---------------------------------------------------------

GO          := go
BPFTool     := bpftool
BIN_DIR     := bin
HEADERS_DIR := headers
VMLINUX_H   := $(HEADERS_DIR)/vmlinux.h

LSM_CMD     := cmd/lsm-file-open
OCI_CMD     := cmd/oci-hook
REPORT_CMD  := cmd/report-generator

BINS := \
	$(BIN_DIR)/lsm-file-open \
	$(BIN_DIR)/oci-hook \
	$(BIN_DIR)/report-generator

# ---- Default target --------------------------------------------------------

.PHONY: all
all: build

# ---- Build -----------------------------------------------------------------

.PHONY: build
build: $(BINS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/lsm-file-open: vmlinux go-generate-lsm | $(BIN_DIR)
	$(GO) build -o $@ ./$(LSM_CMD)

$(BIN_DIR)/oci-hook: vmlinux | $(BIN_DIR)
	$(GO) build -o $@ ./$(OCI_CMD)

$(BIN_DIR)/report-generator: vmlinux | $(BIN_DIR)
	$(GO) build -o $@ ./$(REPORT_CMD)

# ---- vmlinux.h generation --------------------------------------------------

.PHONY: vmlinux
vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@command -v $(BPFTool) >/dev/null 2>&1 || \
		(echo "Error: bpftool not found. Please install bpftool." && exit 1)
	@echo "Generating vmlinux.h"
	mkdir -p $(HEADERS_DIR)
	$(BPFTool) btf dump file /sys/kernel/btf/vmlinux format c > $@

# ---- go generate -----------------------------------------------------------

.PHONY: go-generate-lsm
go-generate-lsm:
	@echo "Running go generate for lsm-file-open"
	$(GO) generate ./$(LSM_CMD)

# ---- Install ---------------------------------------------------------------

.PHONY: install
install: build
	sudo ./scripts/install.sh

# ---- Cleanup ---------------------------------------------------------------

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) $(HEADERS_DIR)/vmlinux.h

