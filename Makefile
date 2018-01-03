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
	@go get -u github.com/smartystreets/goconvey/convey
	@go get -u github.com/go-sql-driver/mysql
	@go get -u github.com/mattn/go-sqlite3

test:
	go test ./... -v -bench=none

benchmark:
	go test ./... -v -bench=. -run=^a