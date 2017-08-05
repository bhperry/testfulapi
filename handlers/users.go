package handlers

import (
	"fmt"
	"net/http"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/satori/go.uuid"
	_ "github.com/go-sql-driver/mysql"

	"golang.org/x/crypto/bcrypt"
)

const (
	DB_USER string = "root"
	DB_PASSWORD string = "password1234"
	DB_SCHEMA string = "userdb"
)

var store = sessions.NewCookieStore([]byte("super-duper-ultra-mega-secret-key"))

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email string `json:"email"`
	Address string `json:"address"`
	Phone string `json:"phone"`
	Extra map[string]string `json:"extra"`
}


func IndexHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session")
	if err != nil {
		HttpResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	authenticated := session.Values["authenticated"]
	if authenticated != nil {
		username := fmt.Sprintf("%s", session.Values["username"])
		details, err := GetUserDetails(username)
		if err != nil {
			HttpResponse(w, http.StatusInternalServerError, err.Error())
			return
		}
		json.NewEncoder(w).Encode(details)
	} else {
		json.NewEncoder(w).Encode("Hello, world!")
	}
}

func NewUserHandler(w http.ResponseWriter, r *http.Request) {
	db := OpenDB()
	defer db.Close()

	//Decode JSON from the POST request
	var user User
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&user)

	//Create a UUID for the new user
	newUuid := uuid.NewV4()

	//Prepare insert query
	insert, err := db.Prepare("INSERT INTO users VALUES(?, ?, ?, ?, ?, ?)")
	if err != nil {
		HttpResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer insert.Close()

	//Get hashed password, and exec the insert query
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	_, err = insert.Exec(newUuid, user.Username, passwordHash, user.Email, user.Address, user.Phone)

	//Error creating new user
	if err != nil {
		if strings.Contains(err.Error(), "Error 1062") {
			HttpResponse(w, http.StatusConflict, "This username is taken")
		} else {
			HttpResponse(w, http.StatusInternalServerError, "Error creating new user")
		}
		return
	}

	//Insert any additional data into user_details table
	err = AddUserDetails(user.Username, user.Extra, db)
	if err != nil {
		HttpResponse(w, http.StatusInternalServerError, err.Error())
	}

	HttpResponse(w, http.StatusOK, "Successfully created new user")
}

func UserHandler(w http.ResponseWriter, r *http.Request) {
	session,_ := store.Get(r, "session")
	authenticated := session.Values["authenticated"]
	vars := mux.Vars(r)

	if authenticated != nil {
		//Check is current user is authorized to access requested data
		username := fmt.Sprintf("%s", session.Values["username"])
		if username != vars["username"] {
			HttpResponse(w, http.StatusUnauthorized, "Unauthorized to access this user's data")
			return
		}

		switch r.Method {
		//Return the user's data
		case "GET": {
			details, err := GetUserDetails(username)
			if err != nil {
				HttpResponse(w, http.StatusInternalServerError, err.Error())
				return
			}

			json.NewEncoder(w).Encode(details)
			break
		}
		//Update the user's data
		case "PUT": {
			db := OpenDB()
			defer db.Close()

			//Decode JSON from PUT request
			var user User
			decoder := json.NewDecoder(r.Body)
			decoder.Decode(&user)

			updateString := ""
			updateValues := make([]interface{}, 0)
			if user.Email != "" {
				updateString += " email = ?"
				updateValues = append(updateValues, user.Email)
			}
			if user.Address != "" {
				updateString += " address = ?"
				updateValues = append(updateValues, user.Address)
			}
			if user.Phone != "" {
				updateString += " phone = ?"
				updateValues = append(updateValues, user.Phone)
			}

			if updateString != "" {
				update, err := db.Prepare("UPDATE users SET" + updateString + " WHERE username='" + username + "'")
				if err != nil {
					HttpResponse(w, http.StatusInternalServerError, err.Error())
					return
				}
				defer update.Close()

				_, err = update.Exec(updateValues...)
				if err != nil {
					HttpResponse(w, http.StatusInternalServerError, err.Error())
					return
				}
			}

			//Insert any additional data into user_details table
			err := AddUserDetails(username, user.Extra, db)
			if err != nil {
				HttpResponse(w, http.StatusInternalServerError, err.Error())
			}

			HttpResponse(w, http.StatusOK, "Updated user")
			break
		}
		case "DELETE": {
			db := OpenDB()
			defer db.Close()

			break
		}
		}
	} else {
		HttpResponse(w, http.StatusUnauthorized, "Unauthenticated")
	}
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	//Get session data
	session,_ := store.Get(r, "session")

	switch r.Method {
	//Authenticate user's login data
	case "POST": {
		db := OpenDB()
		defer db.Close()

		//Decode JSON from POST request
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

		//Compare hashed password and user provided password
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
		if err == bcrypt.ErrMismatchedHashAndPassword {
			HttpResponse(w, http.StatusUnauthorized, "Invalid password")
			return
		}

		//Create new session token for the user
		session.Values["username"] = user.Username
		session.Values["authenticated"] = true
		session.Save(r, w)
		HttpResponse(w, http.StatusOK, "Authenticated")
		break
	}
	//Clear the current user's session
	case "DELETE": {
		//Set cookie to expire immediately
		session.Options.MaxAge = -1
		session.Save(r, w)
		HttpResponse(w, http.StatusOK, "Session deleted")
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

func OpenDB() *sql.DB {
	//Open database connection
	var db, err = sql.Open("mysql", DB_USER + ":" + DB_PASSWORD + "@/" + DB_SCHEMA + "?charset=utf8")
	if err != nil {
		panic(err)
	}

	return db
}

func GetUserDetails(username string) (map[string]string, error) {
	db := OpenDB()
	defer db.Close()

	details := make(map[string]string)
	var userUuid, email, address, phone string
	queryUser := "SELECT uuid, email, address, phone FROM users WHERE username = ?"
	err := db.QueryRow(queryUser, username).Scan(&userUuid, &email, &address, &phone)
	if err == sql.ErrNoRows || err != nil {
		//HttpResponse(w, http.StatusInternalServerError, err.Error())
		return nil, err
	}

	//Add non-blank details to the string map
	if username != "" {
		details["username"] = username
	}
	if email != "" {
		details["email"] = email
	}
	if address != "" {
		details["address"] = address
	}
	if phone != "" {
		details["phone"] = phone
	}

	//Get custom user details
	rows, err := db.Query("SELECT attr, val FROM user_details WHERE uuid = ?", userUuid)

	//Return only if the error isn't a NoRows error
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	var key, value string
	for rows.Next() {
		err = rows.Scan(&key, &value)
		if err != nil {
			return nil, err
		}

		details[key] = value
	}

	return details, nil
}

func AddUserDetails(username string, details map[string]string, db *sql.DB) error {
	//No need to do anything if no details given
	if len(details) == 0 {
		return nil
	}

	//Get user's UUID to access the user_details table
	var userUuid string
	queryUser := "SELECT uuid FROM users WHERE username = ?"
	err := db.QueryRow(queryUser, username).Scan(&userUuid)
	if err == sql.ErrNoRows || err != nil {
		return err
	}

	//Prepare insert or update statement
	insertOrUpdate, err := db.Prepare("INSERT INTO user_details VALUES(?, ?, ?) ON DUPLICATE KEY UPDATE val = ?")
	if err != nil {
		return err
	}
	defer insertOrUpdate.Close()

	//For each detail, insert/update the key,value pair in user_details
	for k, v := range details {
		_, err = insertOrUpdate.Exec(userUuid, k, v, v)
		if err != nil {
			return err
		}
	}
	return nil
}