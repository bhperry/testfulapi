package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"io/ioutil"
	"strings"
	"fmt"
	"errors"
	"time"
	"database/sql/driver"

	"github.com/erikstmartin/go-testdb"
	"github.com/bhperry/testfulapi/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

const BHPERRY_UUID = "cb713068-8278-457a-a782-69e6e8a4efae"
const BHPERRY_HASEHD_PASSWORD = "$2a$10$tc7FyzbvIOEk00Yr9jcdiO4b6qmaqFiiQ1Va.3uE0BsFZGgJc/tau"

var _ = handlers.OpenTestDB()

var redisClient = handlers.NewRedisClient()

//Used to simulate return from a sql exec statement (like INSERT)
type testResult struct{
	lastId int64
	affectedRows int64
}
func (r testResult) LastInsertId() (int64, error){
	return r.lastId, nil
}
func (r testResult) RowsAffected() (int64, error) {
	return r.affectedRows, nil
}

/*-----------    GET /    -----------*/

func TestGetIndexUnauthenticated(t *testing.T) {
	request, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()

	handlers.IndexHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.Code != http.StatusOK {
		t.Error("Error accessing base route\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if responseText != `{"message":"Hello, world!"}`  {
		t.Error("Incorrect response for unauthenticated base route:\n     ", responseText)
	}
}

func TestGetIndexAuthenticated(t *testing.T) {
	//Create stubbed query for test DB
	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"uuid", "email", "address", "phone"}
		rows := ""
		if args[0] == "bhperry" {
			rows = BHPERRY_UUID + `,bhperry94@gmail.com,507 W Wilson St. Apt 602,(314) 406-1345`
		}

		return testdb.RowsFromCSVString(columns, rows), nil
	})

	request, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()

	AuthenticateRequest(response, request, "bhperry")
	handlers.IndexHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.Code != http.StatusOK {
		t.Error("Error accessing base route\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if !strings.Contains(responseText, `"username":"bhperry"`) {
		t.Error("Incorrect response for authenticated base route:\n     ", responseText)
	}
}

/*-----------    POST /user    -----------*/

func TestPostNewUser(t *testing.T) {
	testdb.SetExecWithArgsFunc(func(query string, args []driver.Value) (result driver.Result, err error) {
		if args[0] == "test" {
			return testResult{1, 1}, nil
		}
		return testResult{1, 0}, nil
	})

	request, err := http.NewRequest("POST", "/user", nil)
	if err != nil {
		t.Fatal(err)
	}
	request_data := `{"username":"test","password":"1234"}`
	request.Body = ioutil.NopCloser(strings.NewReader(request_data))

	response := httptest.NewRecorder()

	handlers.NewUserHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.Code != http.StatusOK {
		t.Error("Error creating new user\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if responseText != `{"message":"Successfully created new user"}` {
		t.Error("Error creating a new user:\n     ", responseText)
	}
}

func TestPostNewUserMissingUsername(t *testing.T) {
	request, err := http.NewRequest("POST", "/user", nil)
	if err != nil {
		t.Fatal(err)
	}
	request_data := `{"password":"1234"}`
	request.Body = ioutil.NopCloser(strings.NewReader(request_data))

	response := httptest.NewRecorder()

	handlers.NewUserHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.Code != http.StatusBadRequest {
		t.Error("Should create BadRequest error\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if responseText != "Invalid username or password" {
		t.Error("Request should be invalid:\n     ", responseText)
	}
}

func TestPostNewUserDuplicateUsername(t *testing.T) {
	testdb.SetExecWithArgsFunc(func(query string, args []driver.Value) (result driver.Result, err error) {
		conflictError := errors.New("Error 1062")
		return testResult{1, 0}, conflictError
	})

	request, err := http.NewRequest("POST", "/user", nil)
	if err != nil {
		t.Fatal(err)
	}
	request_data := `{"username":"test","password":"1234"}`
	request.Body = ioutil.NopCloser(strings.NewReader(request_data))

	response := httptest.NewRecorder()

	handlers.NewUserHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.Code != http.StatusConflict {
		t.Error("Should create Conflict error for duplicate entry\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if responseText != "This username is taken" {
		t.Error("Incorrect response for duplicate username:\n     ", responseText)
	}
}

/*-----------    GET /user/{username}    -----------*/

//Tests the same code as for PUT and DELETE unauthenticated
func TestGetUserUnauthenticated(t *testing.T) {
	request, err := http.NewRequest("GET", "/user/bhperry", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()

	handlers.UserHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.Code != http.StatusUnauthorized {
		t.Error("Should be unauthorized to access this endpoint\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if responseText != "Not authenticated"  {
		t.Error("Incorrect response for unauthenticated GET user/{username}:\n     ", responseText)
	}
}

func TestGetUserAuthenticated(t *testing.T) {
	//Create stubbed query for test DB
	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"uuid", "email", "address", "phone"}
		rows := ""
		if args[0] == "bhperry" {
			rows = BHPERRY_UUID + `,bhperry94@gmail.com,507 W Wilson St. Apt 602,(314) 406-1345`
		}

		return testdb.RowsFromCSVString(columns, rows), nil
	})

	router := mux.NewRouter()
	router.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
		//Add authentication to the request and pass on to handler
		AuthenticateRequest(w, r, "bhperry")
		handlers.UserHandler(w, r)
	}).Methods("GET", "PUT", "DELETE")

	testServer := httptest.NewServer(router)
	url := testServer.URL + "/user/bhperry"

	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}

	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.StatusCode != http.StatusOK {
		t.Error("Error getting user data\n   code: ", response.StatusCode, "\n   response: ", responseText)
	}
	if !strings.Contains(responseText, `"username":"bhperry"`) {
		t.Error("Incorrect response for authenticated user:\n     ", responseText)
	}
}

//Tests the same code as for PUT and DELETE unauthorized
func TestGetOtherUserUnauthorized(t *testing.T) {
	router := mux.NewRouter()
	router.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
		//Add authentication for a different user to the request and pass on to handler
		AuthenticateRequest(w, r, "someotherperson")
		handlers.UserHandler(w, r)
	}).Methods("GET", "PUT", "DELETE")

	testServer := httptest.NewServer(router)
	url := testServer.URL + "/user/bhperry"

	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}

	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.StatusCode != http.StatusUnauthorized {
		t.Error("Should be unauthorized to access this endpoint\n   code: ", response.StatusCode, "\n   response: ", responseText)
	}
	if responseText != "Unauthorized to access requested user's data" {
		t.Error("Incorrect response for authenticated but unauthorized user:\n     ", responseText)
	}
}

func TestGetOtherUserAuthorized(t *testing.T) {
	//Create stubbed queries for test DB
	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"admin"}
		rows := ""
		if args[0] == "someotherperson" {
			//IsAdmin query
			rows = `true`
		} else if args[0] == "bhperry" {
			//GetUserDetails query
			columns = []string{"uuid", "email", "address", "phone"}
			rows = BHPERRY_UUID + `,bhperry94@gmail.com,507 W Wilson St. Apt 602,(314) 406-1345`
		}
		return testdb.RowsFromCSVString(columns, rows), nil
	})

	router := mux.NewRouter()
	router.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
		//Add authentication for a different user to the request and pass on to handler
		AuthenticateRequest(w, r, "someotherperson")
		handlers.UserHandler(w, r)
	}).Methods("GET", "PUT", "DELETE")

	testServer := httptest.NewServer(router)
	url := testServer.URL + "/user/bhperry"

	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}

	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.StatusCode != http.StatusOK {
		t.Error("Error getting user data\n   code: ", response.StatusCode, "\n   response: ", responseText)
	}
	if !strings.Contains(responseText, `"username":"bhperry"`) {
		t.Error("Incorrect response for authenticated user:\n     ", responseText)
	}
}

/*-----------    PUT /user/{username}    -----------*/

func TestPutUserAuthenticated(t *testing.T) {
	//Stubbed query for checking if user is admin
	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"admin"}
		rows := ""
		if args[0] == "bhperry" {
			rows = `true`
		}
		return testdb.RowsFromCSVString(columns, rows), nil
	})
	//Stubbed query for updating tables
	testdb.SetExecWithArgsFunc(func(query string, args []driver.Value) (result driver.Result, err error) {
		if args[1] == "email" || args[1] == "random" {
			return testResult{1, 1}, nil
		}
		return testResult{1, 0}, nil
	})

	router := mux.NewRouter()
	router.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
		//Add PUT data to request
		request_data := `{"email":"bhperry94@gmail.com","random":"stuff"}`
		r.Body = ioutil.NopCloser(strings.NewReader(request_data))
		r.Method = "PUT"
		//Add authentication to the request and pass on to handler
		AuthenticateRequest(w, r, "bhperry")
		handlers.UserHandler(w, r)
	}).Methods("GET", "PUT", "DELETE")

	testServer := httptest.NewServer(router)
	url := testServer.URL + "/user/bhperry"

	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}

	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.StatusCode != http.StatusOK {
		t.Error("Error setting user data\n   code: ", response.StatusCode, "\n   response: ", responseText)
	}
	if responseText != `{"message":"Updated user"}` {
		t.Error("Incorrect response for authenticated user:\n     ", responseText)
	}
}

func TestPutOtherUserAuthorized(t *testing.T) {
	//Stubbed query for checking if user is admin
	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"admin"}
		rows := ""
		if args[0] == "bhperry" {
			rows = `true`
		} else {
			rows = `false`
		}
		return testdb.RowsFromCSVString(columns, rows), nil
	})
	//Stubbed query for updating tables
	testdb.SetExecWithArgsFunc(func(query string, args []driver.Value) (result driver.Result, err error) {
		if args[1] == "email" || args[1] == "random" {
			return testResult{1, 1}, nil
		}
		return testResult{1, 0}, nil
	})

	router := mux.NewRouter()
	router.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
		//Add PUT data to request
		request_data := `{"email":"test@gmail.com","random":"stuff"}`
		r.Body = ioutil.NopCloser(strings.NewReader(request_data))
		r.Method = "PUT"
		//Add authentication to the request and pass on to handler
		AuthenticateRequest(w, r, "bhperry")
		handlers.UserHandler(w, r)
	}).Methods("GET", "PUT", "DELETE")

	testServer := httptest.NewServer(router)
	url := testServer.URL + "/user/test"

	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}

	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.StatusCode != http.StatusOK {
		t.Error("Error setting user data\n   code: ", response.StatusCode, "\n   response: ", responseText)
	}
	if responseText != `{"message":"Updated user"}` {
		t.Error("Incorrect response for authenticated user:\n     ", responseText)
	}
}

/*-----------    DELETE /user/{username}    -----------*/

func TestDeleteUserAuthenticated(t *testing.T) {
	//Stubbed query for checking if user is admin
	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{}
		rows := ""
		if query == "SELECT uuid FROM users WHERE username = ?" {
			columns = []string{"uuid"}
			rows = BHPERRY_UUID
		} else if query == "SELECT admin FROM users WHERE username = ?" {
			columns = []string{"admin"}
			rows = "false"
		}
		return testdb.RowsFromCSVString(columns, rows), nil
	})
	//Stubbed query for deleting user
	testdb.SetExecWithArgsFunc(func(query string, args []driver.Value) (result driver.Result, err error) {
		if args[0] == "bhperry" || args[0] == BHPERRY_UUID {
			return testResult{1, 1}, nil
		}
		return testResult{1, 0}, nil
	})

	router := mux.NewRouter()
	router.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
		r.Method = "DELETE"
		//Add authentication to the request and pass on to handler
		AuthenticateRequest(w, r, "bhperry")
		handlers.UserHandler(w, r)
	}).Methods("GET", "PUT", "DELETE")

	testServer := httptest.NewServer(router)
	url := testServer.URL + "/user/bhperry"

	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}

	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.StatusCode != http.StatusOK {
		t.Error("Error deleting user\n   code: ", response.StatusCode, "\n   response: ", responseText)
	}
	if responseText != `{"message":"User deleted"}` {
		t.Error("Incorrect response for deleting authenticated user:\n     ", responseText)
	}
}

func TestDeleteOtherUserAuthorized(t *testing.T) {
	//Stubbed query for checking if user is admin
	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{}
		rows := ""
		if query == "SELECT uuid FROM users WHERE username = ?" {
			columns = []string{"uuid"}
			rows = BHPERRY_UUID
		} else if query == "SELECT admin FROM users WHERE username = ?" {
			columns = []string{"admin"}
			if args[0] == "testAdmin" {
				rows = "true"
			} else {
				rows = "false"
			}
		}
		return testdb.RowsFromCSVString(columns, rows), nil
	})
	//Stubbed query for deleting user
	testdb.SetExecWithArgsFunc(func(query string, args []driver.Value) (result driver.Result, err error) {
		if args[0] == "bhperry" || args[0] == BHPERRY_UUID {
			return testResult{1, 1}, nil
		}
		return testResult{1, 0}, nil
	})

	router := mux.NewRouter()
	router.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
		r.Method = "DELETE"
		//Add authentication to the request and pass on to handler
		AuthenticateRequest(w, r, "testAdmin")
		handlers.UserHandler(w, r)
	}).Methods("GET", "PUT", "DELETE")

	testServer := httptest.NewServer(router)
	url := testServer.URL + "/user/bhperry"

	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}

	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.StatusCode != http.StatusOK {
		t.Error("Error deleting user\n   code: ", response.StatusCode, "\n   response: ", responseText)
	}
	if responseText != `{"message":"User deleted"}` {
		t.Error("Incorrect response for deleting authenticated user:\n     ", responseText)
	}
}

/*-----------    POST /auth    -----------*/

func TestPostAuth(t *testing.T) {
	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"password"}
		rows := ""
		if args[0] == "bhperry" {
			rows = BHPERRY_HASEHD_PASSWORD
		}

		return testdb.RowsFromCSVString(columns, rows), nil
	})

	request, err := http.NewRequest("POST", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	request_data := `{"username":"bhperry","password":"1234"}`
	request.Body = ioutil.NopCloser(strings.NewReader(request_data))

	response := httptest.NewRecorder()

	handlers.AuthHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.Code != http.StatusOK {
		t.Error("Error authenticating user\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if responseText != `{"message":"Authenticated"}` {
		t.Error("Incorrect response from auth:\n     ", responseText)
	}
}

func TestPostAuthBadPassword(t *testing.T) {
	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"password"}
		rows := ""
		if args[0] == "bhperry" {
			rows = BHPERRY_HASEHD_PASSWORD
		}

		return testdb.RowsFromCSVString(columns, rows), nil
	})

	request, err := http.NewRequest("POST", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	request_data := `{"username":"bhperry","password":"123456789"}`
	request.Body = ioutil.NopCloser(strings.NewReader(request_data))

	response := httptest.NewRecorder()

	handlers.AuthHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.Code != http.StatusUnauthorized {
		t.Error("Should be unauthorized\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if responseText != "Invalid password" {
		t.Error("Incorrect response from auth:\n     ", responseText)
	}
}

func TestPostAuthBadUsername(t *testing.T) {
	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"password"}
		rows := ""
		if args[0] == "bhperry" {
			rows = BHPERRY_HASEHD_PASSWORD
		}

		return testdb.RowsFromCSVString(columns, rows), nil
	})

	request, err := http.NewRequest("POST", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	request_data := `{"username":"BADUSERNAME","password":"123456789"}`
	request.Body = ioutil.NopCloser(strings.NewReader(request_data))

	response := httptest.NewRecorder()

	handlers.AuthHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.Code != http.StatusUnauthorized {
		t.Error("Should be unauthorized\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if responseText != "Invalid username" {
		t.Error("Incorrect response from auth:\n     ", responseText)
	}
}

func TestDeleteAuth(t *testing.T) {
	request, err := http.NewRequest("DELETE", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()

	AuthenticateRequest(response, request, "bhperry")

	handlers.AuthHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.Code != http.StatusOK {
		t.Error("Error deleting session token\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if responseText != `{"message":"Session deleted"}` {
		t.Error("Incorrect response from delete auth:\n     ", responseText)
	}
}

func TestDeleteAuthNoSession(t *testing.T) {
	request, err := http.NewRequest("DELETE", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()

	handlers.AuthHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := strings.TrimRight(fmt.Sprintf("%s", body), "\n")
	t.Log(responseText)

	if response.Code != http.StatusUnauthorized {
		t.Error("Should unauthorized, no session to delete\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if responseText != "No session found" {
		t.Error("Incorrect response from delete auth:\n     ", responseText)
	}
}

/*====================================== HELPER METHODS  ======================================*/



func AuthenticateRequest(w http.ResponseWriter, r *http.Request, username string) {
	store := sessions.NewCookieStore([]byte("super-duper-ultra-mega-secret-key"))
	session,_ := store.Get(r, "session")
	session.Values["username"] = username
	session.Save(r, w)

	redisClient.Set(username, true, 86400 * time.Second)
}