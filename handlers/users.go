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
	"io/ioutil"
	"io"
)

//Constants for using mysql database
const (
	DB_USER string = "root"
	DB_PASSWORD string = "password1234"
	DB_SCHEMA string = "userdb"

	DUPLICATE_ENTRY_ERROR string = "Error 1062"
)

//Session data store
var store = sessions.NewCookieStore([]byte("super-duper-ultra-mega-secret-key"))

//Used for determining what data goes in user table and what goes in user_details
var primaryUserData = map[string]bool{"username":true, "password":true, "email":true, "address":true, "phone":true}


/**
	Handles GET /
	Return welcome message to unauthenticated users
	Return user JSON data otherwise
 */
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	//Get user's session data
	session, err := store.Get(r, "session")
	if CheckError(err, w) { return }

	//If authenticated output user data, else output a happy message
	if session.Values["authenticated"] != nil {
		username := fmt.Sprintf("%s", session.Values["username"])
		details, err := GetUserDetails(username)
		if CheckError(err, w) { return }

		//Return user JSON data to the client
		json.NewEncoder(w).Encode(details)
	} else {
		//Return default message to unauthenticated user
		json.NewEncoder(w).Encode("Hello, world!")
	}
}

/**
	Handles POST /user
	Create a new user in the database with the data supplied
	Assigns a UUID, and hashes the password before storing
 */
func NewUserHandler(w http.ResponseWriter, r *http.Request) {
	db := OpenDB()
	defer db.Close()

	//Get JSON data from POST request
	userData, err := DecodeJson(r.Body)
	if CheckError(err, w) { return }


	//Check if username and password are valid
	username, validUsername := userData["username"]
	password, validPassword := userData["password"]
	if !validUsername || !validPassword || len(username) == 0 || len(password) == 0 {
		HttpResponse(w, http.StatusBadRequest, "Invalid username or password")
		return
	}

	//Create a UUID for the new user
	newUuid := uuid.NewV4()

	//Prepare insert query
	insert, err := db.Prepare("INSERT INTO users VALUES(?, ?, ?, ?, ?, ?)")
	if CheckError(err, w) { return }
	defer insert.Close()

	//Get hashed password, and exec the insert query
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	_, err = insert.Exec(newUuid, username, passwordHash, userData["email"], userData["address"], userData["phone"])

	//Remove the primary data from the map
	for k := range userData {
		if _, ok := primaryUserData[k]; ok {
			delete(userData, k)
		}
	}

	//Error creating new user
	if err != nil {
		if strings.Contains(err.Error(), DUPLICATE_ENTRY_ERROR) {
			HttpResponse(w, http.StatusConflict, "This username is taken")
		} else {
			HttpResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	//Insert any additional data into user_details table
	err = AddUserDetails(username, userData, db)
	if CheckError(err, w) { return }

	HttpResponse(w, http.StatusOK, "Successfully created new user")
}

/**
	Handles GET, PUT, DELETE /user/{username}
	Get user data as JSON
	Put updates in user DB if authorized
	Delete user from DB if authorized
 */
func UserHandler(w http.ResponseWriter, r *http.Request) {
	//Get user's session data
	session, _ := store.Get(r, "session")
	authenticated := session.Values["authenticated"]
	vars := mux.Vars(r)

	if authenticated != nil {
		//Check is current user is allowed to access requested data
		username := fmt.Sprintf("%s", session.Values["username"])
		if username != vars["username"] {
			HttpResponse(w, http.StatusUnauthorized, "Unauthorized to access this user's data")
			return
		}

		switch r.Method {
		//Return the user's data
		case "GET": {
			details, err := GetUserDetails(username)
			if CheckError(err, w) { return }

			json.NewEncoder(w).Encode(details)
			break
		}
		//Update the user's data
		case "PUT": {
			db := OpenDB()
			defer db.Close()

			//Get JSON data from PUT request
			userData, err := DecodeJson(r.Body)
			if CheckError(err, w) { return }

			//Query string to be built based on values supplied
			updateString := ""
			//Interface slices to pass into Exec statement
			updateValues := make([]interface{}, 0)

			//Pull out the primary user data from the map and add to user update query
			for k, v := range userData {
				if _, ok := primaryUserData[k]; ok {
					if k == "username" || k == "password" {
						//Not handling updating username or password, as per Challenge DOC
						delete(userData, k)
					} else {
						updateString += fmt.Sprintf(" %s = ?", k)
						updateValues = append(updateValues, v)
						//Remove data that has been used (AMAZING THAT GO LETS YOU DO THIS!!!!)
						delete(userData, k)
					}
				}
			}

			//Run update on users table if any primary data was changed
			if updateString != "" {
				update, err := db.Prepare("UPDATE users SET" + updateString + " WHERE username='" + username + "'")
				if CheckError(err, w) { return }
				defer update.Close()

				_, err = update.Exec(updateValues...)
				if CheckError(err, w) { return }
			}

			//Insert any extra data into user_details table
			err = AddUserDetails(username, userData, db)
			if CheckError(err, w) { return }

			HttpResponse(w, http.StatusOK, "Updated user")
			break
		}
		case "DELETE": {
			db := OpenDB()
			defer db.Close()

			//Get UUID to delete any additional data in user_details table
			userUuid, err := GetUUID(username, db)
			if CheckError(err, w) { return }


			println(username)

			//Delete user record from DB
			deleteQuery, err := db.Prepare("DELETE FROM users WHERE username = ?")
			if CheckError(err, w) { return }
			defer deleteQuery.Close()
			deleteQuery.Exec(username)

			//Delete user details from DB
			deleteDetailsQuery, err := db.Prepare("DELETE FROM user_details WHERE uuid = ?")
			if CheckError(err, w) { return }
			defer deleteDetailsQuery.Close()
			_, err = deleteDetailsQuery.Exec(userUuid)
			CheckError(err, w)

			//Expire the deleted user's session token
			session.Options.MaxAge = -1
			session.Save(r, w)
			HttpResponse(w, http.StatusOK, "User deleted")
			break
		}
		}
	} else {
		HttpResponse(w, http.StatusUnauthorized, "Unauthenticated")
	}
}

/**
	Handles POST, DELETE /auth
	Post user's credentials to get session token
	Delete current user's session token
 */
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	//Get user's session data
	session, _ := store.Get(r, "session")

	switch r.Method {
	//Authenticate user's login data
	case "POST": {
		db := OpenDB()
		defer db.Close()

		//Decode JSON from POST request
		type UserLogin struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		var login UserLogin
		decoder := json.NewDecoder(r.Body)
		decoder.Decode(&login)

		if login.Username == "" || login.Password == "" {
			HttpResponse(w, http.StatusBadRequest, "Invalid login credentials")
		}

		//Check if the username exists and correct password was entered
		var hashedPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", login.Username).Scan(&hashedPassword)
		if err == sql.ErrNoRows || err != nil {
			HttpResponse(w, http.StatusUnauthorized, "Invalid username")
			return
		}

		//Compare hashed password and user provided password
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(login.Password))
		if err == bcrypt.ErrMismatchedHashAndPassword {
			HttpResponse(w, http.StatusUnauthorized, "Invalid password")
			return
		}

		//Create new session token for the user
		session.Values["username"] = login.Username
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

/**
	Handles GET /utility
	Serves the request utility for easy access to API
 */
func RequestUtilityHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w,r, "static/index.html")
}


/*====================================== HELPER METHODS  ======================================*/


/**
	Check if an internal server error has occurred,
	and send error message to client if needed
 */
func CheckError(err error, w http.ResponseWriter) bool {
	if err != nil {
		HttpResponse(w, http.StatusInternalServerError, err.Error())
		return true
	}
	return false
}

/**
	Helper method for writing messages to the client
 */
func HttpResponse(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}

/**
	Open a connection to the MySQL database
 */
func OpenDB() *sql.DB {
	var db, err = sql.Open("mysql", DB_USER + ":" + DB_PASSWORD + "@/" + DB_SCHEMA + "?charset=utf8")
	if err != nil {
		panic(err)
	}
	return db
}

/**
	Collect all data pertaining to the given user in a string map
 */
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

/**
	Insert or update any extra data for a user
		(anything besides the basics given in the Coding Challenge doc)
	TODO: Delete data at Key if Value = ""?
 */
func AddUserDetails(username string, details map[string]string, db *sql.DB) error {
	//No need to do anything if no details given
	if len(details) == 0 {
		return nil
	}

	//Get user's UUID to access the user_details table
	userUuid, err := GetUUID(username, db)
	if err != nil {
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
/**
	Gets the UUID for the given username
 */
func GetUUID(username string, db *sql.DB) (string, error) {
	var userUuid string
	queryUser := "SELECT uuid FROM users WHERE username = ?"
	err := db.QueryRow(queryUser, username).Scan(&userUuid)
	if err == sql.ErrNoRows || err != nil {
		return "", err
	}
	return userUuid, nil
}

/**
	Decode JSON data from a request Body and return as a string map
 */
func DecodeJson(body io.ReadCloser) (map[string]string, error) {
	//Get byte data
	data, _ := ioutil.ReadAll(body)

	//Unmarshal into an interface
	var f interface{}
	err := json.Unmarshal(data, &f)
	if err != nil {
		return nil, err
	}

	//Assert underlying structure of the interface
	jsonMap := f.(map[string]interface{})

	//Convert interface map into a string map
	userData := make(map[string]string)
	for k, v := range jsonMap {
		userData[k] = v.(string)
	}

	return userData, nil
}