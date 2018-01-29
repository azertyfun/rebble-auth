package rebbleHandlers

import (
	"fmt"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

// AdminRebuildDBHandler allows an administrator to rebuild the database from
// the application directory after hitting a single API end point.
func AdminRebuildDBHandler(ctx *HandlerContext, w http.ResponseWriter, r *http.Request) (int, error) {
	dbHandler := ctx.Database

	sqlStmt := `
			drop table if exists users;
			create table users (
				id integer not null primary key,
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
				userId integer not null,
				expires integer not null
			);
			delete from userSessions;

			drop table if exists userLogins;
			create table userLogins (
				id integer not null primary key,
				userId integer not null,
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

	log.Print("Rebble Auth Database rebuilt successfully.")
	return http.StatusOK, nil
}
