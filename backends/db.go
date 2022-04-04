package backends

import (
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// OpenDatabase opens the database and performs a ping to make sure the
// database is up.
// Taken from brocaar's lora-app-server: https://github.com/brocaar/lora-app-server
func OpenDatabase(dsn, engine string, tries int, maxLifeTime int64) (*sqlx.DB, error) {

	db, err := sqlx.Open(engine, dsn)
	if err != nil {
		return nil, errors.Wrap(err, "database connection error")
	}

	if tries == 0 {
		tries = 1
	}

	for tries != 0 {
		if err = db.Ping(); err != nil {
			log.Errorf("ping database %s error, will retry in 2s: %s", engine, err)
			time.Sleep(2 * time.Second)
		} else {
			break
		}

		if tries > 0 {
			tries--
		}
	}

	// Return last ping error when done trying.
	if tries == 0 {
		return nil, fmt.Errorf("couldn't ping database %s: %s", engine, err)
	}

	if maxLifeTime > 0 {
		db.SetConnMaxLifetime(time.Duration(maxLifeTime) * time.Second)
	}

	return db, nil
}
