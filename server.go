package main

import (
	"net/http"
	"flag"
	"time"
	"log"

	"github.com/urfave/negroni"
	"github.com/gorilla/mux"
	"github.com/bhperry/testfulapi/handlers"

	//Added so as to grab testing package on initial 'go get' command
	_"github.com/erikstmartin/go-testdb"
)

/**
	Setup routing handlers, initialize DB connections, and start the server
 */
func main() {
	var dir string
	flag.StringVar(&dir, "dir", ".", "the directory to serve files from. Defaults to the current dir")
	flag.Parse()

	//Open MySQL DB
	db := handlers.OpenDB()
	defer db.Close()
	handlers.InitDB()

	//Open Redis
	redisClient := handlers.NewRedisClient()
	defer redisClient.Close()

	//Connect endpoints with their handlers
	router := mux.NewRouter()
	router.HandleFunc("/", handlers.IndexHandler).Methods("GET")
	router.HandleFunc("/user", handlers.NewUserHandler).Methods("POST")
	router.HandleFunc("/user/{username}", handlers.UserHandler).Methods("GET", "PUT", "DELETE")
	router.HandleFunc("/auth", handlers.AuthHandler).Methods("POST", "DELETE")
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


