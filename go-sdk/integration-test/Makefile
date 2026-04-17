VGO=go
GOBIN := $(shell $(VGO) env GOPATH)/bin

# Expect that Zeto compiles with CGO disabled
CGO_ENABLED=0
GOGC=30

.DELETE_ON_ERROR:

all: e2e go-mod-tidy
go-mod-tidy: .ALWAYS
		$(VGO) mod tidy
e2e:
		$(VGO) test -count=1  -v ./...
.ALWAYS: ;
clean:
		$(VGO) clean
		rm -f *.so
deps:
		$(VGO) get -u ./...
