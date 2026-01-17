package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	amqp "github.com/rabbitmq/amqp091-go"
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
// ESTRUTURAS
// ============================================================================

type PaymentRequest struct {
	AccountID string  `json:"accountId"`
	Amount    float64 `json:"amount"`
	Currency  string  `json:"currency"`
	CPF       string  `json:"cpf,omitempty"`        // Dado sensível
	CardNumber string `json:"cardNumber,omitempty"` // Dado sensível
}

type PaymentResponse struct {
	PaymentID   string    `json:"paymentId"`
	Status      string    `json:"status"`
	ProcessedAt time.Time `json:"processedAt"`
}

type PaymentData struct {
	PaymentID   string
	AccountID   string
	Amount      float64
	Currency    string
	CPF         string // Criptografado
	CardNumber  string // Criptografado
	CreatedAt   time.Time
}

var (
	logger           *zap.Logger
	tracer           trace.Tracer
	authServiceURL   string
	secretManagerURL string
	secretManagerToken string
	encryptionKey    []byte

	// Métricas de segurança
	authFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "payment_auth_failures_total",
			Help: "Total authentication failures",
		},
		[]string{"reason"},
	)

	authorizationFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "payment_authorization_failures_total",
			Help: "Total authorization failures",
		},
		[]string{"reason"},
	)

	// Métricas RED (da aula 6)
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
		},
		[]string{"method", "endpoint"},
	)

	paymentsProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "payments_processed_total",
			Help: "Total payments processed",
		},
		[]string{"status", "currency"},
	)
)

// ============================================================================
// TRACING E LOGGING
// ============================================================================

func initTracing() {
	jaegerEndpoint := os.Getenv("JAEGER_ENDPOINT")
	if jaegerEndpoint == "" {
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
			semconv.ServiceName("payment-service"),
		)),
		tracesdk.WithSampler(tracesdk.TraceIDRatioBased(1.0)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer = otel.Tracer("payment-service")
}

func initLogger() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		panic(err)
	}
}

// ============================================================================
// MASCARAMENTO DE DADOS SENSÍVEIS
// ============================================================================

func maskCPF(cpf string) string {
	if len(cpf) < 4 {
		return "***"
	}
	return "***.***.***-" + cpf[len(cpf)-2:]
}

func maskCardNumber(card string) string {
	if len(card) < 4 {
		return "****"
	}
	return "****-****-****-" + card[len(card)-4:]
}

func maskToken(token string) string {
	if len(token) < 20 {
		return "***"
	}
	return token[:10] + "..." + token[len(token)-10:]
}

// ============================================================================
// CRIPTOGRAFIA
// ============================================================================

func initEncryption() error {
	// Em produção, obter chave do secret manager
	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		// Gerar chave temporária (em produção, sempre usar secret manager)
		key = "temporary-key-32-bytes-long!!"
		logger.Warn("Using temporary encryption key - use secret manager in production!")
	}

	// Garantir que a chave tem 32 bytes (AES-256)
	keyBytes := []byte(key)
	if len(keyBytes) < 32 {
		// Padding
		for len(keyBytes) < 32 {
			keyBytes = append(keyBytes, 0)
		}
	} else if len(keyBytes) > 32 {
		keyBytes = keyBytes[:32]
	}

	encryptionKey = keyBytes
	return nil
}

func encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// ============================================================================
// AUTENTICAÇÃO E AUTORIZAÇÃO
// ============================================================================

func validateToken(tokenString string) (*jwt.Token, error) {
	// Validar com auth-service
	if authServiceURL != "" {
		reqBody := map[string]string{"token": tokenString}
		jsonData, _ := json.Marshal(reqBody)
		
		resp, err := http.Post(authServiceURL+"/auth/validate", "application/json", bytes.NewBuffer(jsonData))
		if err == nil && resp.StatusCode == http.StatusOK {
			var validateResp struct {
				Valid bool `json:"valid"`
			}
			json.NewDecoder(resp.Body).Decode(&validateResp)
			resp.Body.Close()
			
			if validateResp.Valid {
				// Parse local para obter claims
				return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
					return []byte("dummy"), nil // Em produção, validar assinatura
				})
			}
		}
	}

	// Fallback: validação local simplificada
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("dummy"), nil
	})
}

func extractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("invalid authorization format")
	}

	return strings.TrimPrefix(authHeader, "Bearer "), nil
}

func hasScope(claims jwt.MapClaims, requiredScope string) bool {
	scopesInterface, ok := claims["scopes"]
	if !ok {
		return false
	}

	// Tentar como slice de interface{}
	if scopes, ok := scopesInterface.([]interface{}); ok {
		for _, scope := range scopes {
			if scopeStr, ok := scope.(string); ok && scopeStr == requiredScope {
				return true
			}
		}
		return false
	}

	// Tentar como string (separada por espaços)
	if scopeStr, ok := scopesInterface.(string); ok {
		scopes := strings.Split(scopeStr, " ")
		for _, scope := range scopes {
			if scope == requiredScope {
				return true
			}
		}
		return false
	}

	// Tentar como slice de strings
	if scopes, ok := scopesInterface.([]string); ok {
		for _, scope := range scopes {
			if scope == requiredScope {
				return true
			}
		}
		return false
	}

	return false
}

func authenticateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := r.Context()

		// Health check não precisa de autenticação
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			next(w, r)
			return
		}

		tokenString, err := extractToken(r)
		if err != nil {
			authFailures.WithLabelValues("missing_token").Inc()
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		token, err := validateToken(tokenString)
		if err != nil || !token.Valid {
			authFailures.WithLabelValues("invalid_token").Inc()
			maskedToken := maskToken(tokenString)
			logger.Warn("auth_failed",
				zap.String("token_masked", maskedToken),
				zap.Error(err),
			)
			http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			authFailures.WithLabelValues("invalid_claims").Inc()
			http.Error(w, "Unauthorized: invalid claims", http.StatusUnauthorized)
			return
		}

		// Verificar expiração
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				authFailures.WithLabelValues("expired_token").Inc()
				http.Error(w, "Unauthorized: token expired", http.StatusUnauthorized)
				return
			}
		}

		// Adicionar claims ao contexto
		ctx = context.WithValue(ctx, "claims", claims)
		ctx = context.WithValue(ctx, "user", claims["sub"])

		// Log SEM expor token
		maskedToken := maskToken(tokenString)
		logger.Info("request_authenticated",
			zap.String("user", fmt.Sprintf("%v", claims["sub"])),
			zap.String("token_masked", maskedToken),
			zap.String("path", r.URL.Path),
		)

		// Executar handler
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next(rw, r.WithContext(ctx))

		// Métricas
		duration := time.Since(start)
		httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, fmt.Sprintf("%d", rw.statusCode)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration.Seconds())
	}
}

// ============================================================================
// HANDLERS
// ============================================================================

func handlePayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx, span := tracer.Start(ctx, "payment.process")
	defer span.End()

	claims, ok := ctx.Value("claims").(jwt.MapClaims)
	if !ok {
		authorizationFailures.WithLabelValues("missing_claims").Inc()
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Verificar autorização (scope)
	if !hasScope(claims, "payments:write") {
		authorizationFailures.WithLabelValues("insufficient_scope").Inc()
		logger.Warn("authorization_failed",
			zap.String("user", fmt.Sprintf("%v", claims["sub"])),
			zap.String("required_scope", "payments:write"),
		)
		http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
		return
	}

	var req PaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Criptografar dados sensíveis
	encryptedCPF := ""
	encryptedCard := ""
	var err error

	if req.CPF != "" {
		encryptedCPF, err = encrypt(req.CPF)
		if err != nil {
			logger.Error("encryption_failed", zap.String("field", "cpf"), zap.Error(err))
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	}

	if req.CardNumber != "" {
		encryptedCard, err = encrypt(req.CardNumber)
		if err != nil {
			logger.Error("encryption_failed", zap.String("field", "cardNumber"), zap.Error(err))
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	}

	// Armazenar (simulado - em produção seria em banco criptografado)
	paymentID := fmt.Sprintf("pay-%d-%d", time.Now().UnixNano(), rand.Intn(10000))
	_ = PaymentData{
		PaymentID:  paymentID,
		AccountID:  req.AccountID,
		Amount:     req.Amount,
		Currency:   req.Currency,
		CPF:        encryptedCPF,
		CardNumber: encryptedCard,
		CreatedAt:  time.Now(),
	}

	// Log SEM dados sensíveis
	logger.Info("payment_processed",
		zap.String("payment_id", paymentID),
		zap.String("account_id", req.AccountID),
		zap.Float64("amount", req.Amount),
		zap.String("currency", req.Currency),
		zap.String("cpf_masked", maskCPF(req.CPF)),
		zap.String("card_masked", maskCardNumber(req.CardNumber)),
		zap.String("user", fmt.Sprintf("%v", claims["sub"])),
	)

	span.SetAttributes(
		attribute.String("payment.id", paymentID),
		attribute.String("payment.account_id", req.AccountID),
		attribute.Float64("payment.amount", req.Amount),
		attribute.String("payment.currency", req.Currency),
		// NUNCA adicionar dados sensíveis ao span
	)

	// Publicar evento (sem dados sensíveis)
	rabbitURL := os.Getenv("RABBIT_URL")
	if rabbitURL != "" {
		conn, err := amqp.Dial(rabbitURL)
		if err == nil {
			ch, _ := conn.Channel()
			ch.ExchangeDeclare("payments", "fanout", true, false, false, false, nil)

			event := map[string]interface{}{
				"event":     "PaymentCreated",
				"paymentId": paymentID,
				"accountId": req.AccountID,
				"amount":    req.Amount,
				"currency":  req.Currency,
				"ts":        time.Now().UnixMilli(),
				// NUNCA incluir dados sensíveis no evento
			}

			body, _ := json.Marshal(event)
			ch.Publish("payments", "", false, false, amqp.Publishing{
				Body:        body,
				ContentType: "application/json",
			})
			conn.Close()
		}
	}

	// Métricas
	paymentsProcessed.WithLabelValues("success", req.Currency).Inc()

	response := PaymentResponse{
		PaymentID:   paymentID,
		Status:      "PROCESSED",
		ProcessedAt: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
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
	authServiceURL = os.Getenv("AUTH_SERVICE_URL")
	secretManagerURL = os.Getenv("SECRET_MANAGER_URL")
	secretManagerToken = os.Getenv("SECRET_MANAGER_TOKEN")

	if err := initEncryption(); err != nil {
		logger.Fatal("Failed to initialize encryption", zap.Error(err))
	}

	// Rotas
	http.HandleFunc("/payments", authenticateMiddleware(handlePayment))
	http.HandleFunc("/health", handleHealth)
	http.Handle("/metrics", promhttp.Handler())

	logger.Info("payment-service listening on :8080",
		zap.String("service", "payment-service"),
		zap.String("version", "1.0.0"),
		zap.String("auth_service", authServiceURL),
	)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}
