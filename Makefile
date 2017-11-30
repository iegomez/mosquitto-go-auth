all: 
	go build -buildmode=c-shared -o go-auth.so
	go build pw-gen/pw.go

requirements:
	@echo "Installing development tools"
	@go get -u github.com/pkg/errors
	@go get -u github.com/dgrijalva/jwt-go
	@go get -u github.com/jmoiron/sqlx
	@go get -u github.com/lib/pq
	@go get -u github.com/go-redis/redis
	@go get -u golang.org/x/crypto/pbkdf2