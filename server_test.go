package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"github.com/bhperry/testfulapi/handlers"
	"io/ioutil"
	"fmt"
)

func TestGetMainUnauthenticated(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()

	handlers.IndexHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := fmt.Sprintf("%s", body)

	if response.Code != http.StatusOK {
		t.Error("Error loading main page, code: ", response.Code)
	}
	if responseText != "Hello, world!" {
		t.Error("Incorrect response for unauthenticated main page")
	}
}

func TestGetMainAuthenticated(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()

	handlers.IndexHandler(response, request)
	body, _ := ioutil.ReadAll(response.Body)
	responseText := fmt.Sprintf("%s", body)

	if response.Code != http.StatusOK {
		t.Error("Error loading main page, code: ", response.Code)
	}
	if responseText != "Hello, world!" {
		t.Error("Incorrect response for unauthenticated main page")
	}
}

