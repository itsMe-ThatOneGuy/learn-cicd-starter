package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	validReq, _ := http.NewRequest("", "", nil)
	validReq.Header.Set("Authorization", "ApiKey a1234")
	_, err := GetAPIKey(validReq.Header)
	if err != nil {
		t.Errorf("validReq: Expected error to be nil: %v", err)
	}

	reqEmpty, _ := http.NewRequest("", "", nil)
	reqEmpty.Header.Set("Authorization", "")
	_, err = GetAPIKey(reqEmpty.Header)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("reqEmpty: Expected ErrNoAuthHeaderIncluded: %v", err)
	}

	reqEmptyKey, _ := http.NewRequest("", "", nil)
	reqEmptyKey.Header.Set("Authorization", "ApiKey")
	_, err = GetAPIKey(reqEmptyKey.Header)
	if err == nil {
		t.Errorf("reqEmptyKey: Expected error malformed auth header: %v", err)
	}

	wrongAuth, _ := http.NewRequest("", "", nil)
	wrongAuth.Header.Set("Authorization", "Bearer b1234")
	_, err = GetAPIKey(wrongAuth.Header)
	if err == nil {
		t.Errorf("wrongAuth: Expected error malformed auth header: %v", err)
	}

}
