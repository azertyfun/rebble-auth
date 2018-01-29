package rebbleHandlers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

type PebbleApplication struct {
	Author   string `json:"author"`
	AuthorId string `json:"developer_id"`
}

// PebbleAppList contains a list of PebbleApplication. It matches the format of Pebble API answers.
type PebbleAppList struct {
	Apps []*PebbleApplication `json:"data"`
}

// walkFiles is intended to quickly crawl the pebble application folder
// in-order to re-build the users database.
func walkFiles(root string) (<-chan string, <-chan error) {
	// Create a couple of channels to communicate with the main process.
	// (multi-threading FTW!)
	paths := make(chan string)
	errf := make(chan error, 1)

	// Crawl the directory in the background.
	go func() {
		defer close(paths)
		errf <- filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Println(err)
			}
			if info.IsDir() {
				return nil
			}
			if strings.HasSuffix(info.Name(), ".json") {
				paths <- path
			}
			return nil
		})
	}()

	// Return the channels so that our goroutine can communicate with the main
	// thread.
	return paths, errf
}

// AdminRebuildDBHandler allows an administrator to rebuild the database from
// the application directory after hitting a single API end point.
func AdminRebuildDBHandler(ctx *HandlerContext, w http.ResponseWriter, r *http.Request) (int, error) {
	dbHandler := ctx.Database

	sqlStmt := `
			drop table if exists users;
			create table users (
				id text not null primary key,
				provider text not null,
				sub text not null,
				name text not null,
				type text nont null default 'user',
				pebbleMirror integer not null,
				disabled integer not null
			);
			delete from users;

			drop table if exists userSessions;
			create table userSessions (
				id integer not null primary key,
				accessToken text not null,
				ssoAccessToken text not null,
				userId text not null,
				expires integer not null
			);
			delete from userSessions;

			drop table if exists userLogins;
			create table userLogins (
				id integer not null primary key,
				userId text not null,
				remoteIp text not null,
				time integer not null,
				success integer not null
			);
			delete from users;
		`
	_, err := dbHandler.Exec(sqlStmt)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("%q: %s", err, sqlStmt)
	}

	users := make(map[string]string)

	path, errc := walkFiles("PebbleAppStore/")
	for item := range path {
		f, err := ioutil.ReadFile(item)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		data := PebbleAppList{}

		err = json.Unmarshal(f, &data)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		if len(data.Apps) != 1 {
			panic("Data is not the size of 1")
		}

		// Create author if it doesn't exist
		if _, ok := users[data.Apps[0].Author]; !ok {
			users[data.Apps[0].AuthorId] = data.Apps[0].Author
		}
	}

	if err := <-errc; err != nil {
		return http.StatusInternalServerError, err
	}

	tx, err := dbHandler.Begin()
	defer tx.Rollback()
	for id, user := range users {
		tx.Exec("INSERT INTO users(id, provider, sub, name, type, pebbleMirror, disabled) VALUES (?, 'none', '', ?, 'users', 1, 0)", id, user)
	}
	tx.Commit()

	log.Print("Rebble Auth Database rebuilt successfully.")
	return http.StatusOK, nil
}
