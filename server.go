package main

import (
	"net/http"
	"fmt"
	"database/sql"
	"flag"
	"time"
	"log"
	"encoding/json"
	"strings"

	"github.com/urfave/negroni"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/satori/go.uuid"
	_ "github.com/go-sql-driver/mysql"

	"golang.org/x/crypto/bcrypt"

	//"github.com/bhperry/testfulapi/handlers"
)

var db, err = sql.Open("mysql", "root:password1234@/userdb?charset=utf8")

var store = sessions.NewCookieStore([]byte("super-duper-ultra-mega-secret-key"))


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
	defer db.Close()
	var dir string
	flag.StringVar(&dir, "dir", ".", "the directory to serve files from. Defaults to the current dir")
	flag.Parse()

	//Set max age for session cookies to one day
	//store.Options = &sessions.Options{
	//	MaxAge: 86400,
	//}

	//Setup endpoints with their handlers
	router := mux.NewRouter()
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(dir))))
	router.HandleFunc("/", IndexHandler).Methods("GET")
	router.HandleFunc("/user/", NewUserHandler).Methods("POST")
	router.HandleFunc("/user/{username}/", UserHandler).Methods("GET", "POST", "DELETE")
	router.HandleFunc("/auth/", AuthHandler).Methods("POST", "DELETE")
	router.HandleFunc("/utility/", RequestUtilityHandler).Methods("GET")

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

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session")
	if err != nil {
		HttpResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	authenticated := session.Values["authenticated"]
	if authenticated != nil {
		var userUuid, email, address, phone string
		username := fmt.Sprintf("%s", session.Values["username"])
		queryUser := "SELECT uuid, email, address, phone FROM users WHERE username = ?"
		err := db.QueryRow(queryUser, username).Scan(&userUuid, &email, &address, &phone)
		if err == sql.ErrNoRows || err != nil {
			HttpResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		//rows, err := db.Query("SELECT key, val FROM user_details WHERE uuid = ?")
		fmt.Fprintf(w, "User %s authenticated", session.Values["username"])
	} else {
		json.NewEncoder(w).Encode("Hello, world!")
	}
}

func NewUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&user)

	fmt.Printf("USER: %q\n", user)

	newUuid := uuid.NewV4()
	//TODO: Is this the right format?
	insert, err := db.Prepare("INSERT INTO users VALUES(?, ?, ?, ?, ?, ?)")
	CheckErr(err)
	defer insert.Close()

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	_, err = insert.Exec(newUuid, user.Username, passwordHash, user.Email, user.Address, user.Phone)

	if CheckErr(err) {
		if strings.Contains(err.Error(), "Error 1062") {
			HttpResponse(w, http.StatusConflict, "This username is taken")
		} else {
			HttpResponse(w, http.StatusInternalServerError, "Error creating new user")
		}
	} else {
		json.NewEncoder(w).Encode("Successfully created new user")
	}
}

func UserHandler(w http.ResponseWriter, r *http.Request) {
	//session := sessions.GetSession(r)
	//authenticated := session.Get("authenticated")

	session,_ := store.Get(r, "session")
	authenticated := session.Values["authenticated"]
	vars := mux.Vars(r)

	switch r.Method {
	case "GET": {
		if authenticated != nil {
			fmt.Fprintf(w, "THIS IS USER: %q\n", vars["username"])
		} else {
			fmt.Fprint(w, "Not authenticated")
		}
		break
	}
	case "POST": {

		break
	}
	case "DELETE": {

		break
	}
	}
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	//session := sessions.GetSession(r)
	session,_ := store.Get(r, "session")

	switch r.Method {
	case "POST": {
		var user User
		decoder := json.NewDecoder(r.Body)
		decoder.Decode(&user)

		//Check if the username exists and correct password was entered
		var hashedPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", user.Username).Scan(&hashedPassword)
		if err == sql.ErrNoRows || err != nil {
			HttpResponse(w, http.StatusUnauthorized, "Invalid username")
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
		if err == bcrypt.ErrMismatchedHashAndPassword {
			HttpResponse(w, http.StatusUnauthorized, "Invalid password")
			return
		}

		//session.Set("authenticated", true)
		session.Values["username"] = user.Username
		session.Values["authenticated"] = true
		session.Save(r, w)
		HttpResponse(w, http.StatusOK, "Authenticated")
		break
	}
	case "DELETE": {
		//Clear the current user's session by expiring the cookie
		session.Options.MaxAge = -1
		session.Save(r, w)
		HttpResponse(w, http.StatusOK, "Unauthenticated")
		break
	}
	}
}

func RequestUtilityHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w,r, "static/index.html")
}

func CheckErr(err error) bool {
	if err != nil {
		println(err.Error())
		return true
	}
	return false
}

func HttpResponse(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}