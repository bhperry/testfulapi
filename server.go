package main

import (
	"net/http"
	"flag"
	"time"
	"log"

	"github.com/urfave/negroni"
	"github.com/gorilla/mux"
	"github.com/bhperry/testfulapi/handlers"
)

/**
	Setup routing handlers and start the server
 */
func main() {
	var dir string
	flag.StringVar(&dir, "dir", ".", "the directory to serve files from. Defaults to the current dir")
	flag.Parse()

	db := handlers.OpenDB()
	defer db.Close()
	handlers.InitDB()

	redisClient := handlers.NewRedisClient()
	defer redisClient.Close()

	//Connect endpoints with their handlers. Handlers wrapped to pass in db connection
	router := mux.NewRouter()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handlers.IndexHandler(w, r)
	}).Methods("GET")
	router.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		handlers.NewUserHandler(w, r)
	}).Methods("POST")
	router.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
		handlers.UserHandler(w, r)
	}).Methods("GET", "PUT", "DELETE")
	router.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		handlers.AuthHandler(w, r)
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


