package backends

import (
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// OpenDatabase opens the database and performs a ping to make sure the
// database is up.
// Taken from brocaar's lora-app-server: https://github.com/brocaar/lora-app-server
func OpenDatabase(dsn, engine string) (*sqlx.DB, error) {

	db, err := sqlx.Open(engine, dsn)
	if err != nil {
		return nil, errors.Wrap(err, "database connection error")
	}

	for {
		if err = db.Ping(); err != nil {
			log.Errorf("ping database error, will retry in 2s: %s", err)
			time.Sleep(2 * time.Second)
		} else {
			break
		}
	}

	return db, nil
}
