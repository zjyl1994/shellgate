package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	h := Middleware(true, "secret", next)
	for _, tc := range []struct {
		header, origin string
		want           int
	}{{want: 401}, {header: "Bearer wrong", want: 401}, {header: "Bearer secret", want: 204}, {header: "Bearer secret", origin: "https://x", want: 403}} {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("Authorization", tc.header)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%+v got %d", tc, w.Code)
		}
	}
}
