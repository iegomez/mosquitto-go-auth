all: 
	go build -buildmode=c-shared -o go-auth.so
	go build pw-gen/pw.go