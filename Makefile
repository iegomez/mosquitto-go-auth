all:
	go build -buildmode=c-archive go-auth.go
	go build -buildmode=c-shared -o go-auth.so
	go build pw-gen/pw.go

requirements:
	dep ensure -v

dev-requirements:
	go get -u github.com/golang/dep/cmd/dep
	go get -u github.com/smartystreets/goconvey

test:
	go test ./backends -v -bench=none -count=1

benchmark:
	go test ./backends -v -bench=. -run=^a