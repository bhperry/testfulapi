package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"io/ioutil"
	"fmt"

	"github.com/bhperry/testfulapi/handlers"
	"github.com/gorilla/sessions"
	"strings"
	"net/url"
)

func TestGetIndexUnauthenticated(t *testing.T) {
	request, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()

	handlers.IndexHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := fmt.Sprintf("%s", body)
	t.Log(responseText)

	if response.Code != http.StatusOK {
		t.Error("Error loading main page\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if strings.TrimRight(responseText, "\n") != "\"Hello, world!\""  {
		t.Error("Incorrect response for unauthenticated main page:\n     ", responseText)
	}
}

func TestGetIndexAuthenticated(t *testing.T) {
	request, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()

	store := sessions.NewCookieStore([]byte("super-duper-ultra-mega-secret-key"))
	session,_ := store.Get(request, "session")
	session.Values["username"] = "bhperry"
	session.Values["authenticated"] = true
	session.Save(request, response)

	handlers.IndexHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := fmt.Sprintf("%s", body)
	t.Log(responseText)

	if response.Code != http.StatusOK {
		t.Error("Error loading main page\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if !strings.Contains(responseText, "bhperry") {
		t.Error("Incorrect response for authenticated main page:\n     ", responseText)
	}
}

func TestPostNewUser(t *testing.T) {
	request := &http.Request{
		Method: "POST",
		URL: &url.URL{Path: "/user"},
		Form: url.Values{},
	}
	response := httptest.NewRecorder()

	handlers.NewUserHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := fmt.Sprintf("%s", body)
	t.Log(responseText)

	if response.Code != http.StatusOK {
		t.Error("Error creating new user\n   code: ", response.Code, "\n   response: ", responseText)
	}
	if !strings.Contains(responseText, "bhperry") {
		t.Error("Incorrect response for authenticated main page:\n     ", responseText)
	}
}

