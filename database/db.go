package database

import (
	"database/sql"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type Sqlite struct {
	Db *sql.DB
}

var (
	sqlite     *Sqlite
	initDBOnce sync.Once
)

const file string = "db.sqlite"
const create string = `
  CREATE TABLE IF NOT EXISTS "urls"  (
	"short_url"	TEXT NOT NULL UNIQUE,
	"original_url"	TEXT NOT NULL,
	"created_at"	TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY("short_url")
	);
	`

func newDB() {
	initDBOnce.Do(func() {
		db, err := sql.Open("sqlite3", file)
		if err != nil {
			panic(err)
		}
		if _, err := db.Exec(create); err != nil {
			panic(err)
		}

		sqlite = &Sqlite{
			Db: db,
		}
	})
}

func (q *Sqlite) Close() {
	q.Db.Close()
}

func GetDB() *Sqlite {
	if sqlite == nil {
		newDB()
	}

	return sqlite
}
