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
	"github.com/go-redis/redis"

	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"io"
	"strconv"
	"time"
	"errors"
)

const (
	//Constants for using mysql database
	DB_USER string = "root"
	DB_PASSWORD string = "password1234"
	DB_NAME string = "userdb"
	DB_SCHEMA string = "userschema"
	DUPLICATE_ENTRY_ERROR string = "Error 1062"

	//Redis constants
	REDIS_CLIENT_ADDR string = "localhost:6379"
	REDIS_CLIENT_PASSWORD string = ""
	REDIS_DB int = 0
)

//Session data store
var store = sessions.NewCookieStore([]byte("super-duper-ultra-mega-secret-key"))

//Used for determining what data goes in 'user' table and what goes in 'user_details'
var primaryUserData = map[string]bool{"username":true, "password":true, "email":true, "address":true, "phone":true, "admin":true}

var db *sql.DB

var redisClient *redis.Client


/**
	Handles GET /
	Return welcome message to unauthenticated users
	Return user JSON data otherwise
 */
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	//Get user's session data
	session, err := store.Get(r, "session")
	if CheckError(err, w) { return }

	currentUser, err := CheckAuthentication(session.Values["username"])
	//If authenticated output user data, else output a happy message
	if err == nil {
		//Get user data
		details, err := GetUserDetails(currentUser)
		if CheckError(err, w) { return }

		//Return user JSON data to the client
		json.NewEncoder(w).Encode(map[string]interface{}{"user":details})
	} else {
		//Return default message to unauthenticated user
		json.NewEncoder(w).Encode(map[string]string{"message": "Hello, world!"})
	}
}

/**
	Handles POST /user
	Create a new user in the database with the data supplied
	Assigns a UUID, and hashes the password before storing
 */
func NewUserHandler(w http.ResponseWriter, r *http.Request) {
	//Get user's session data
	session, _ := store.Get(r, "session")

	currentUser, err := CheckAuthentication(session.Values["username"])
	currentUserIsAdmin := false
	if err == nil {
		currentUserIsAdmin = IsAdmin(currentUser)
	}

	//Get JSON data from POST request
	userData, err := DecodeJson(r.Body)
	if CheckError(err, w) { return }

	//Check if username and password are valid
	username := userData["username"]
	password := userData["password"]
	if username == "" || password == "" {
		http.Error(w, "Invalid username or password", http.StatusBadRequest)
		return
	}

	//Create a UUID for the new user
	newUuid := uuid.NewV4()
	//Get salted and hashed password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	//Build the sql query
	newUserQuery := "INSERT INTO users(uuid, username, password, email, address, phone"
	newUserValues := make([]interface{}, 0)
	newUserValues = append(newUserValues, newUuid, username, passwordHash, userData["email"], userData["address"], userData["phone"])

	//Only allow authenticated admins to create new admin accounts
	newUserIsAdmin, _ := strconv.ParseBool(userData["admin"])
	if newUserIsAdmin && currentUserIsAdmin {
		newUserQuery += ", admin) VALUES(?, ?, ?, ?, ?, ?, ?)"
		newUserValues = append(newUserValues, newUserIsAdmin)
	} else {
		newUserQuery += ") VALUES(?, ?, ?, ?, ?, ?)"
	}

	//Prepare and exec the insert query
	insert, err := db.Prepare(newUserQuery)
	if CheckError(err, w) { return }
	defer insert.Close()

	_, err = insert.Exec(newUserValues...)
	if err != nil {
		if strings.Contains(err.Error(), DUPLICATE_ENTRY_ERROR) {
			http.Error(w, "This username is taken", http.StatusConflict)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	//Remove the primary data from the map
	for k := range userData {
		if _, ok := primaryUserData[k]; ok {
			delete(userData, k)
		}
	}

	//Insert any additional data into user_details table
	err = AddUserDetails(username, userData)
	if CheckError(err, w) { return }

	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully created new user"})
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
	vars := mux.Vars(r)

	currentUser, err := CheckAuthentication(session.Values["username"])
	if err != nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	//Check is current user is allowed to access requested data
	requestedUser := vars["username"]
	currentUserIsAdmin := IsAdmin(currentUser)

	//If authenticated user is not admin, don't give access to other users
	if requestedUser != currentUser && !currentUserIsAdmin {
		http.Error(w, "Unauthorized to access requested user's data", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	//Return the user's data
	case "GET": {
		details, err := GetUserDetails(requestedUser)
		if CheckError(err, w) { return }

		//Return JSON user data to the client
		json.NewEncoder(w).Encode(map[string]interface{}{"user":details})
		break
	}
	//Update the user's data
	case "PUT": {
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
					//Only allow admins to set the admin property
					if k == "admin" && currentUserIsAdmin {
						//Only set the property if a real boolean value was given
						setAdmin, err := strconv.ParseBool(v)
						if err == nil {
							updateString += fmt.Sprintf(" %s = ?", k)
							updateValues = append(updateValues, setAdmin)
						}
					} else {
						updateString += fmt.Sprintf(" %s = ?", k)
						updateValues = append(updateValues, v)
					}
					//Remove data that has been used
					delete(userData, k)
				}
			}
		}

		//Run update on users table if any primary data was changed
		if updateString != "" {
			//Prepare statement
			update, err := db.Prepare("UPDATE users SET" + updateString + " WHERE username = ?")
			if CheckError(err, w) { return }
			defer update.Close()

			//Add requested username to values slice for passing into Exec
			updateValues = append(updateValues, requestedUser)

			_, err = update.Exec(updateValues...)
			if CheckError(err, w) { return }
		}

		//Insert any extra data into user_details table
		err = AddUserDetails(requestedUser, userData)
		if CheckError(err, w) { return }

		json.NewEncoder(w).Encode(map[string]string{"message": "Updated user"})
		break
	}
	case "DELETE": {
		//Get UUID to delete any additional data in user_details table
		userUuid, err := GetUUID(requestedUser)
		if CheckError(err, w) { return }

		//Delete user record from DB
		deleteQuery, err := db.Prepare("DELETE FROM users WHERE username = ?")
		if CheckError(err, w) { return }
		defer deleteQuery.Close()
		deleteQuery.Exec(requestedUser)

		//Delete user details from DB
		deleteDetailsQuery, err := db.Prepare("DELETE FROM user_details WHERE uuid = ?")
		if CheckError(err, w) { return }
		defer deleteDetailsQuery.Close()
		_, err = deleteDetailsQuery.Exec(userUuid)
		CheckError(err, w)

		if currentUser == requestedUser {
			//Expire the deleted user's session token
			session.Options.MaxAge = -1
			session.Save(r, w)
		}
		redisClient.Set(requestedUser, false, -2 * time.Second)
		json.NewEncoder(w).Encode(map[string]string{"message": "User deleted"})
		break
	}
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
		//Decode JSON from POST request
		type UserLogin struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		var login UserLogin
		decoder := json.NewDecoder(r.Body)
		decoder.Decode(&login)

		if login.Username == "" || login.Password == "" {
			http.Error(w, "Invalid login credentials", http.StatusBadRequest)
			return
		}

		//Check if the username exists and correct password was entered
		var hashedPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", login.Username).Scan(&hashedPassword)
		if err == sql.ErrNoRows || err != nil {
			http.Error(w, "Invalid username", http.StatusUnauthorized)
			return
		}

		//Compare hashed password and user provided password
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(login.Password))
		if err == bcrypt.ErrMismatchedHashAndPassword {
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return
		}

		//Create new session token for the user
		session.Values["username"] = login.Username
		session.Save(r, w)

		redisClient.Set(login.Username, true, 86400 * time.Second)
		json.NewEncoder(w).Encode(map[string]string{"message": "Authenticated"})
		break
	}
	//Clear the current user's session
	case "DELETE": {
		username, err := CheckAuthentication(session.Values["username"])
		if err != nil {
			http.Error(w, "No session found", http.StatusUnauthorized)
			return
		}

		//Set cookie to expire immediately
		session.Options.MaxAge = -1
		session.Save(r, w)

		redisClient.Set(username, false, -2 * time.Second)

		json.NewEncoder(w).Encode(map[string]string{"message": "Session deleted"})
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	return false
}

/**
	Collect all data pertaining to the given user in a string map
 */
func GetUserDetails(username string) (map[string]string, error) {
	details := make(map[string]string)
	var userUuid, email, address, phone string
	queryUser := "SELECT uuid, email, address, phone FROM users WHERE username = ?"
	err := db.QueryRow(queryUser, username).Scan(&userUuid, &email, &address, &phone)
	if err == sql.ErrNoRows || err != nil {
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
func AddUserDetails(username string, details map[string]string) error {
	//No need to do anything if no details given
	if len(details) == 0 {
		return nil
	}

	//Get user's UUID to access the user_details table
	userUuid, err := GetUUID(username)
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
func GetUUID(username string) (string, error) {
	var userUuid string
	queryUser := "SELECT uuid FROM users WHERE username = ?"
	err := db.QueryRow(queryUser, username).Scan(&userUuid)
	if err == sql.ErrNoRows || err != nil {
		return "", err
	}
	return userUuid, nil
}

/**
	Determine if the given user is an admin
 */
func IsAdmin(username string) bool {
	var isAdmin bool
	err := db.QueryRow("SELECT admin FROM users WHERE username = ?", username).Scan(&isAdmin)
	if err != nil {
		return false
	}
	return isAdmin
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

/**
	Setup a connection to the MySQL database
 */
func OpenDB() *sql.DB {
	var err error
	db, err = sql.Open("mysql", DB_USER + ":" + DB_PASSWORD + "@/" + DB_NAME + "?charset=utf8")
	if err != nil {
		panic(err)
	}
	return db
}

/**
	Setup a Test database
 */
func OpenTestDB() *sql.DB {
	var err error
	db, err = sql.Open("testdb", "")
	if err != nil {
		panic(err)
	}
	return db
}

/**
	Check if the schema and tables all exist, and create them if not
 */
func InitDB() {
	//userdb schema
	_, err := db.Exec("CREATE SCHEMA IF NOT EXISTS " + DB_SCHEMA)
	if err != nil {
		panic(err)
	}

	_,err = db.Exec("USE " + DB_SCHEMA)
	if err != nil {
		panic(err)
	}

	println("Create users")
	//users table
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS `users` (" +
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

	println("Create user_details")
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS `user_details` (" +
		"`uuid` CHAR(36) NOT NULL," +
		"`attr` VARCHAR(200) NOT NULL," +
		"`val` VARCHAR(200) NOT NULL," +
		"PRIMARY KEY (`uuid`, `attr`)" +
		");")
	if err != nil {
		panic(err)
	}
}

func NewRedisClient() *redis.Client {
	redisClient = redis.NewClient(&redis.Options {
		Addr: REDIS_CLIENT_ADDR,
		Password: REDIS_CLIENT_PASSWORD,
		DB: REDIS_DB,
	})
	return redisClient
}

func CheckAuthentication(username interface{}) (string, error) {
	if username != nil {
		user := username.(string)
		authenticated, _ := strconv.ParseBool(redisClient.Get(user).Val())
		if authenticated {
			return user, nil
		}
	}
	return "", errors.New("Not authenticated")
}