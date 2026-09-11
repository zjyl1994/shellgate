package auth

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

type Role string

const (
	ExecutionRole Role = "execution"
	LogReaderRole Role = "log_reader"
)

type roleKey struct{}

func RoleFromContext(ctx context.Context) Role {
	role, _ := ctx.Value(roleKey{}).(Role)
	return role
}

func Middleware(enabled bool, executionToken, logToken string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			http.Error(w, "origin requests are forbidden", http.StatusForbidden)
			return
		}
		role := ExecutionRole
		if enabled {
			const prefix = "Bearer "
			v := r.Header.Get("Authorization")
			provided := strings.TrimPrefix(v, prefix)
			switch {
			case strings.HasPrefix(v, prefix) && subtle.ConstantTimeCompare([]byte(provided), []byte(executionToken)) == 1:
				role = ExecutionRole
			case logToken != "" && strings.HasPrefix(v, prefix) && subtle.ConstantTimeCompare([]byte(provided), []byte(logToken)) == 1:
				role = LogReaderRole
			default:
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), roleKey{}, role)))
	})
}
