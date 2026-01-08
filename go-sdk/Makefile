VGO=go
GOFILES := $(shell find ./internal ./pkg -name '*.go' -print)
GOBIN := $(shell $(VGO) env GOPATH)/bin
LINT := $(GOBIN)/golangci-lint

# Expect that Zeto compiles with CGO disabled
CGO_ENABLED=0
GOGC=30

.DELETE_ON_ERROR:

all: test go-mod-tidy
test: deps lint
		$(VGO) test -v ./internal/... -cover -coverprofile=coverage.txt -covermode=atomic -timeout=30s ${TEST_ARGS}
coverage.html:
		$(VGO) tool cover -html=coverage.txt
coverage: test coverage.html
lint: ${LINT}
		GOGC=20 $(LINT) run -v --timeout 5m
${LINT}:
		$(VGO) install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8
go-mod-tidy: .ALWAYS
		$(VGO) mod tidy
e2e: test
		$(VGO) test -count=1  -v ./integration-test
.ALWAYS: ;
clean:
		$(VGO) clean
		rm -f *.so
deps:
		$(VGO) get -u ./...
