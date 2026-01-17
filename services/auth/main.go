package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// ============================================================================
// ESTRUTURAS E CONFIGURAÇÕES
// ============================================================================

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken string   `json:"access_token"`
	TokenType   string   `json:"token_type"`
	ExpiresIn   int      `json:"expires_in"`
	Scope       string   `json:"scope"`
	Roles       []string `json:"roles,omitempty"`
}

type ValidateRequest struct {
	Token string `json:"token"`
}

type ValidateResponse struct {
	Valid   bool     `json:"valid"`
	Claims  jwt.MapClaims `json:"claims,omitempty"`
	Expires *time.Time    `json:"expires,omitempty"`
}

type ServiceTokenRequest struct {
	ServiceName string `json:"service_name"`
}

// Usuários e permissões (em produção, viria de banco de dados)
var users = map[string]struct {
	Password string
	Roles    []string
	Scopes   []string
}{
	"user1": {
		Password: "password123",
		Roles:    []string{"user"},
		Scopes:   []string{"payments:read", "payments:write"},
	},
	"admin": {
		Password: "admin123",
		Roles:    []string{"admin", "user"},
		Scopes:   []string{"payments:read", "payments:write", "payments:admin", "secrets:read", "secrets:write"},
	},
	"viewer": {
		Password: "viewer123",
		Roles:    []string{"viewer"},
		Scopes:   []string{"payments:read"},
	},
}

// Serviços autorizados para service-to-service tokens
var authorizedServices = map[string]struct {
	Scopes []string
}{
	"payment-service": {
		Scopes: []string{"payments:write", "secrets:read"},
	},
	"antifraud-service": {
		Scopes: []string{"payments:read", "secrets:read"},
	},
	"notification-service": {
		Scopes: []string{"payments:read", "secrets:read"},
	},
	"auth-service": {
		Scopes: []string{"auth:admin", "secrets:read", "secrets:write"},
	},
}

var (
	logger    *zap.Logger
	tracer    trace.Tracer
	jwtSecret string
	jwtExpiry time.Duration

	// Métricas de segurança
	authAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_attempts_total",
			Help: "Total authentication attempts",
		},
		[]string{"status", "type"},
	)

	authSuccess = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_success_total",
			Help: "Total successful authentications",
		},
		[]string{"user_type"},
	)

	authFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_failures_total",
			Help: "Total authentication failures",
		},
		[]string{"reason"},
	)

	tokenValidations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "token_validations_total",
			Help: "Total token validations",
		},
		[]string{"status"},
	)
)

// ============================================================================
// TRACING E LOGGING
// ============================================================================

func initTracing() {
	jaegerEndpoint := os.Getenv("JAEGER_ENDPOINT")
	if jaegerEndpoint == "" {
		logger.Warn("No Jaeger endpoint configured, tracing disabled")
		return
	}

	collectorURL := fmt.Sprintf("http://%s/api/traces", jaegerEndpoint)
	exporter, err := jaeger.New(
		jaeger.WithCollectorEndpoint(
			jaeger.WithEndpoint(collectorURL),
		),
	)
	if err != nil {
		logger.Error("Failed to create Jaeger exporter", zap.Error(err))
		return
	}

	tp := tracesdk.NewTracerProvider(
		tracesdk.WithBatcher(exporter),
		tracesdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("auth-service"),
		)),
		tracesdk.WithSampler(tracesdk.TraceIDRatioBased(1.0)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer = otel.Tracer("auth-service")
}

func initLogger() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		panic(err)
	}
}

// ============================================================================
// JWT E AUTENTICAÇÃO
// ============================================================================

func generateToken(username string, roles []string, scopes []string, isService bool) (string, error) {
	now := time.Now()
	expiresAt := now.Add(jwtExpiry)

	claims := jwt.MapClaims{
		"sub":    username,
		"iat":    now.Unix(),
		"exp":    expiresAt.Unix(),
		"roles":  roles,
		"scopes": scopes,
		"type":   "user",
	}

	if isService {
		claims["type"] = "service"
		claims["service_name"] = username
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func validateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return token, nil
}

func maskToken(token string) string {
	if len(token) < 20 {
		return "***"
	}
	return token[:10] + "..." + token[len(token)-10:]
}

// ============================================================================
// HANDLERS
// ============================================================================

func handleLogin(w http.ResponseWriter, r *http.Request) {
	_, span := tracer.Start(r.Context(), "auth.login")
	defer span.End()

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		authAttempts.WithLabelValues("error", "invalid_request").Inc()
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	span.SetAttributes(
		attribute.String("auth.username", req.Username),
		attribute.Bool("auth.is_service", false),
	)

	// Buscar usuário
	user, exists := users[req.Username]
	if !exists || user.Password != req.Password {
		authFailures.WithLabelValues("invalid_credentials").Inc()
		authAttempts.WithLabelValues("failure", "user").Inc()
		
		// Log SEM expor a senha
		logger.Warn("auth_failed",
			zap.String("username", req.Username),
			zap.String("reason", "invalid_credentials"),
		)
		
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Gerar token
	token, err := generateToken(req.Username, user.Roles, user.Scopes, false)
	if err != nil {
		authFailures.WithLabelValues("token_generation_error").Inc()
		logger.Error("token_generation_failed",
			zap.String("username", req.Username),
			zap.Error(err),
		)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	authSuccess.WithLabelValues("user").Inc()
	authAttempts.WithLabelValues("success", "user").Inc()

	// Log SEM expor o token completo
	maskedToken := maskToken(token)
	logger.Info("auth_success",
		zap.String("username", req.Username),
		zap.String("token_masked", maskedToken),
		zap.Strings("roles", user.Roles),
		zap.Strings("scopes", user.Scopes),
	)

	response := LoginResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(jwtExpiry.Seconds()),
		Scope:       strings.Join(user.Scopes, " "),
		Roles:       user.Roles,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	_, span := tracer.Start(r.Context(), "auth.validate")
	defer span.End()

	var req ValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		tokenValidations.WithLabelValues("error").Inc()
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token, err := validateToken(req.Token)
	if err != nil {
		tokenValidations.WithLabelValues("invalid").Inc()
		json.NewEncoder(w).Encode(ValidateResponse{Valid: false})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		tokenValidations.WithLabelValues("invalid").Inc()
		json.NewEncoder(w).Encode(ValidateResponse{Valid: false})
		return
	}

	tokenValidations.WithLabelValues("valid").Inc()

	exp, ok := claims["exp"].(float64)
	var expires *time.Time
	if ok {
		t := time.Unix(int64(exp), 0)
		expires = &t
	}

	json.NewEncoder(w).Encode(ValidateResponse{
		Valid:   true,
		Claims:  claims,
		Expires: expires,
	})
}

func handleServiceToken(w http.ResponseWriter, r *http.Request) {
	_, span := tracer.Start(r.Context(), "auth.service_token")
	defer span.End()

	// Verificar autenticação do serviço (simplificado - em produção seria mais robusto)
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		authFailures.WithLabelValues("missing_auth").Inc()
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Em produção, validar token de serviço aqui
	// Por simplicidade, aceitamos qualquer Authorization header para serviços

	var req ServiceTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	service, exists := authorizedServices[req.ServiceName]
	if !exists {
		authFailures.WithLabelValues("unauthorized_service").Inc()
		logger.Warn("unauthorized_service_token_request",
			zap.String("service_name", req.ServiceName),
		)
		http.Error(w, "Unauthorized service", http.StatusForbidden)
		return
	}

	token, err := generateToken(req.ServiceName, []string{"service"}, service.Scopes, true)
	if err != nil {
		authFailures.WithLabelValues("token_generation_error").Inc()
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	authSuccess.WithLabelValues("service").Inc()
	authAttempts.WithLabelValues("success", "service").Inc()

	maskedToken := maskToken(token)
	logger.Info("service_token_generated",
		zap.String("service_name", req.ServiceName),
		zap.String("token_masked", maskedToken),
		zap.Strings("scopes", service.Scopes),
	)

	response := LoginResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(jwtExpiry.Seconds()),
		Scope:       strings.Join(service.Scopes, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Capturar response
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next(rw, r)

		duration := time.Since(start)
		logger.Info("http_request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", rw.statusCode),
			zap.Duration("duration_ms", duration),
			zap.String("service", "auth-service"),
		)
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	initLogger()
	defer logger.Sync()

	initTracing()

	// Configuração
	jwtSecret = os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "default-secret-change-in-production"
		logger.Warn("Using default JWT secret - change in production!")
	}

	expiryStr := os.Getenv("JWT_EXPIRY")
	if expiryStr == "" {
		jwtExpiry = 1 * time.Hour
	} else {
		if expiry, err := strconv.Atoi(expiryStr); err == nil {
			jwtExpiry = time.Duration(expiry) * time.Second
		} else {
			jwtExpiry = 1 * time.Hour
		}
	}

	// Rotas
	http.HandleFunc("/auth/login", loggingMiddleware(handleLogin))
	http.HandleFunc("/auth/validate", loggingMiddleware(handleValidate))
	http.HandleFunc("/auth/service-token", loggingMiddleware(handleServiceToken))
	http.HandleFunc("/health", handleHealth)
	http.Handle("/metrics", promhttp.Handler())

	logger.Info("auth-service listening on :8080",
		zap.String("service", "auth-service"),
		zap.String("version", "1.0.0"),
		zap.Duration("jwt_expiry", jwtExpiry),
	)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}
