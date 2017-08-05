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

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email string `json:"email"`
	Address string `json:"address"`
	Phone string `json:"phone"`
	Extra map[string]string `json:"extra"`
}

/** Setup routing handlers and start server listening on port 8000
 */
func main() {
	var dir string
	flag.StringVar(&dir, "dir", ".", "the directory to serve files from. Defaults to the current dir")
	flag.Parse()

	//Set max age for session cookies to one day
	//store.Options = &sessions.Options{
	//	MaxAge: 86400,
	//}

	//Setup endpoints with their handlers
	router := mux.NewRouter()
	router.HandleFunc("/", handlers.IndexHandler).Methods("GET")
	router.HandleFunc("/user", handlers.NewUserHandler).Methods("POST")
	router.HandleFunc("/user/{username}", handlers.UserHandler).Methods("GET", "PUT", "DELETE")
	router.HandleFunc("/auth", handlers.AuthHandler).Methods("POST", "DELETE")
	router.HandleFunc("/utility", handlers.RequestUtilityHandler).Methods("GET")

	n := negroni.New()
	//n.Use(sessions.Sessions("global_session_store", store))
	n.UseHandler(router)

	srv := &http.Server{
		Handler: n,
		Addr: "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout: 15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
	//http.ListenAndServe(":8000", n)
}

//CREATE TABLE `userdb`.`user_details` (
//`uuid` CHAR(36) NOT NULL,
//`key` VARCHAR(200) NOT NULL,
//`value` VARCHAR(200) NOT NULL,
//PRIMARY KEY (`uuid`));
