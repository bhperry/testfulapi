package main

import (
	"net/http"
	"flag"
	"time"
	"log"

	"github.com/urfave/negroni"
	"github.com/gorilla/mux"
	"github.com/bhperry/testfulapi/handlers"
	"database/sql"
)

const (
	//Constants for using mysql database
	DB_USER string = "root"
	DB_PASSWORD string = "password1234"
	DB_SCHEMA string = "userdb"
)

/**
	Setup routing handlers and start the server
 */
func main() {
	var dir string
	flag.StringVar(&dir, "dir", ".", "the directory to serve files from. Defaults to the current dir")
	flag.Parse()

	db := OpenDB()
	defer db.Close()
	InitDB(db)

	redisClient := handlers.NewRedisClient()
	defer redisClient.Close()

	//Connect endpoints with their handlers. Handlers wrapped to pass in db connection
	router := mux.NewRouter()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handlers.IndexHandler(w, r, db)
	}).Methods("GET")
	router.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		handlers.NewUserHandler(w, r, db)
	}).Methods("POST")
	router.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
		handlers.UserHandler(w, r, db)
	}).Methods("GET", "PUT", "DELETE")
	router.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		handlers.AuthHandler(w, r, db)
	}).Methods("POST", "DELETE")
	router.HandleFunc("/utility", handlers.RequestUtilityHandler).Methods("GET")

	n := negroni.New()
	n.UseHandler(router)

	srv := &http.Server{
		Handler: n,
		Addr: "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout: 15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

/**
	Setup a connection to the MySQL database
 */
func OpenDB() *sql.DB {
	var db, err = sql.Open("mysql", DB_USER + ":" + DB_PASSWORD + "@/" + DB_SCHEMA + "?charset=utf8")
	if err != nil {
		panic(err)
	}
	return db
}

/**
	Check if the schema and tables all exist, and create them if not
 */
func InitDB(db *sql.DB) {
	//userdb schema
	_, err := db.Query("CREATE DATABASE IF NOT EXISTS " + DB_SCHEMA)
	if err != nil {
		panic(err)
	}

	//users table
	_, err = db.Query("CREATE TABLE IF NOT EXISTS `users` (" +
		"`uuid` char(36) NOT NULL," +
		"`username` varchar(100) NOT NULL," +
		"`password` varchar(64) NOT NULL," +
		"`email` varchar(254) DEFAULT NULL," +
		"`address` varchar(200) DEFAULT NULL," +
		"`phone` varchar(30) DEFAULT NULL," +
		"`admin` tinyint(4) DEFAULT '0'," +
		"PRIMARY KEY (`uuid`)," +
		"UNIQUE KEY `username_UNIQUE` (`username`)" +
		");")
	if err != nil {
		panic(err)
	}

	_, err = db.Query("CREATE TABLE IF NOT EXISTS `user_details` (" +
		"`uuid` CHAR(36) NOT NULL," +
		"`attr` VARCHAR(200) NOT NULL," +
		"`val` VARCHAR(200) NOT NULL," +
		"PRIMARY KEY (`uuid`, `attr`)" +
		");")
	if err != nil {
		panic(err)
	}
}


