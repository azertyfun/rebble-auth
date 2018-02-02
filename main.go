package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"pebble-dev/rebble-auth/common"
	"pebble-dev/rebble-auth/db"
	"pebble-dev/rebble-auth/rebbleHandlers"
	"pebble-dev/rebble-auth/sso"

	"github.com/gorilla/handlers"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pborman/getopt"
)

type config struct {
	Ssos           []sso.Sso `json":ssos"`
	AllowedDomains []string  `json:"allowed_domains"`
	HTTPS          bool      `json:"https"`
	Database       string    `json:"database"`
}

func main() {
	config := config{
		AllowedDomains: []string{"http://localhost:8080, http://localhost:8081"},
		HTTPS:          true,
		Database:       "./rebble-auth.db",
	}

	file, err := ioutil.ReadFile("./rebble-auth.json")
	if err != nil {
		panic("Could not load rebble-auth.json: " + err.Error())
	}
	err = json.Unmarshal(file, &config)
	if err != nil {
		panic("Could not parse rebble-api.json: " + err.Error())
	}

	var version bool

	getopt.BoolVarLong(&version, "version", 'V', "Get the current version info")
	getopt.BoolVarLong(&config.HTTPS, "https", 'h', "Set whether or not to use HTTPS (defaults to true)")
	getopt.StringVarLong(&config.Database, "database", 'd', "Specify a specific SQLite database path (defaults to ./rebble-auth.db)")
	getopt.Parse()
	if version {
		fmt.Fprintf(os.Stderr, "Version %s\nBuild Host: %s\nBuild Date: %s\nBuild Hash: %s\n", common.Buildversionstring, common.Buildhost, common.Buildstamp, common.Buildgithash)
		return
	}

	rebbleHandlers.AllowedDomains = config.AllowedDomains

	log.Println("Initializing SSO providers...")
	for i, sso := range config.Ssos {
		s, err := sso.Initialize()
		if err != nil {
			log.Printf("Could not initialize SSO provider %v: %v", config.Ssos[i].Name, err)
			return
		}
		config.Ssos[i] = s
	}
	log.Println("Done.")

	database, err := sql.Open("sqlite3", config.Database)
	if err != nil {
		panic("Could not connect to database" + err.Error())
	}

	dbHandler := db.Handler{database}

	// construct the context that will be injected in to handlers
	context := &rebbleHandlers.HandlerContext{&dbHandler, config.Ssos}

	r := rebbleHandlers.Handlers(context)
	loggedRouter := handlers.LoggingHandler(os.Stdout, r)
	http.Handle("/", r)
	log.Println("Serving HTTP(S)")
	if config.HTTPS {
		err = http.ListenAndServeTLS(":8082", "server.crt", "server.key", loggedRouter)
	} else {
		err = http.ListenAndServe(":8082", loggedRouter)
	}
	if err != nil {
		panic("Could not listen and serve TLS: " + err.Error())
	}
}
