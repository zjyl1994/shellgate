package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

func Middleware(enabled bool, token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			http.Error(w, "origin requests are forbidden", http.StatusForbidden)
			return
		}
		if enabled {
			const prefix = "Bearer "
			v := r.Header.Get("Authorization")
			if !strings.HasPrefix(v, prefix) || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(v, prefix)), []byte(token)) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
