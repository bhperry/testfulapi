package main

import (
	//"fmt"
	"net/http"

	"github.com/urfave/negroni"
	"github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
	"github.com/gorilla/mux"
	//"github.com/gorilla/sessions"
	"github.com/satori/go.uuid"
	_ "github.com/go-sql-driver/mysql"

	"golang.org/x/crypto/bcrypt"

	//"github.com/bhperry/testfulapi/handlers"
	"fmt"
	"encoding/base64"
	"crypto/rand"
	"database/sql"
	"flag"
	"time"
	"log"
	"encoding/json"
	"strings"
)

var db, err = sql.Open("mysql", "root:password1234@/userdb?charset=utf8")


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


	store := cookiestore.New([]byte("super-duper-ultra-secret-key"))
	store.Options(sessions.Options{
		MaxAge: 86400,
	})

	router := mux.NewRouter()
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(dir))))
	router.HandleFunc("/", IndexHandler).Methods("GET")
	router.HandleFunc("/user/", NewUserHandler).Methods("POST")
	router.HandleFunc("/user/{username}/", UserHandler).Methods("GET", "POST", "DELETE")
	router.HandleFunc("/auth/", AuthHandler).Methods("POST", "DELETE")
	router.HandleFunc("/utility/", RequestUtilityHandler).Methods("GET")

	n := negroni.New()
	n.Use(sessions.Sessions("global_session_store", store))
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
	session := sessions.GetSession(r)
	authenticated := session.Get("authenticated")

	if authenticated != nil {
		fmt.Fprint(w, "User authenticated")
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
	session := sessions.GetSession(r)
	authenticated := session.Get("authenticated")
	vars := mux.Vars(r)

	switch r.Method {
	case "GET": {
		println(authenticated)
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
	session := sessions.GetSession(r)

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

		session.Set("authenticated", true)
		HttpResponse(w, http.StatusOK, "Authenticated")
		break
	}
	case "DELETE": {
		//Clear the current user's session
		session.Delete("authenticated")
		session.Clear()
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

func NewSessionToken() (string, error) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	if err != nil {
		return "", err
	}

	token := base64.URLEncoding.EncodeToString(randBytes)
	return token, err
}

func HttpResponse(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}