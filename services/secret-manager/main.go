package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

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
// ESTRUTURAS
// ============================================================================

type Secret struct {
	Key         string    `json:"key"`
	Value       string    `json:"value"`
	Version     int       `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	RotatedAt   *time.Time `json:"rotated_at,omitempty"`
	LastAccessed *time.Time `json:"last_accessed,omitempty"`
}

type AuditLog struct {
	Key         string    `json:"key"`
	Service     string    `json:"service"`
	Action      string    `json:"action"`
	Timestamp   time.Time `json:"timestamp"`
	Success     bool      `json:"success"`
}

type SecretStore struct {
	mu      sync.RWMutex
	secrets map[string]*Secret
	audit   []AuditLog
}

var store = &SecretStore{
	secrets: make(map[string]*Secret),
	audit:   make([]AuditLog, 0),
}

// Tokens de serviço autorizados (em produção, viria de banco/config)
var serviceTokens = map[string]string{
	"service-token-payment":      "payment-service",
	"service-token-antifraud":    "antifraud-service",
	"service-token-notification": "notification-service",
	"service-token-auth":         "auth-service",
}

var (
	logger *zap.Logger
	tracer trace.Tracer

	// Métricas
	secretAccess = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "secret_access_total",
			Help: "Total secret accesses",
		},
		[]string{"key", "action", "status"},
	)

	secretRotations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "secret_rotations_total",
			Help: "Total secret rotations",
		},
		[]string{"key", "status"},
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
			semconv.ServiceName("secret-manager"),
		)),
		tracesdk.WithSampler(tracesdk.TraceIDRatioBased(1.0)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer = otel.Tracer("secret-manager")
}

func initLogger() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		panic(err)
	}
}

// ============================================================================
// FUNÇÕES DE SEGREDO
// ============================================================================

func generateRandomSecret(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func maskSecret(secret string) string {
	if len(secret) < 8 {
		return "***"
	}
	return secret[:4] + "..." + secret[len(secret)-4:]
}

func authenticateService(r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", false
	}

	// Remover "Bearer " se presente
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		authHeader = authHeader[7:]
	}

	service, exists := serviceTokens[authHeader]
	return service, exists
}

// ============================================================================
// HANDLERS
// ============================================================================

func handleGetSecret(w http.ResponseWriter, r *http.Request) {
	_, span := tracer.Start(r.Context(), "secret.get")
	defer span.End()

	service, authenticated := authenticateService(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	key := r.URL.Path[len("/secrets/"):]
	if key == "" {
		http.Error(w, "Key required", http.StatusBadRequest)
		return
	}

	store.mu.RLock()
	secret, exists := store.secrets[key]
	store.mu.RUnlock()

	if !exists {
		secretAccess.WithLabelValues(key, "get", "not_found").Inc()
		store.mu.Lock()
		store.audit = append(store.audit, AuditLog{
			Key:       key,
			Service:   service,
			Action:    "get",
			Timestamp: time.Now(),
			Success:   false,
		})
		store.mu.Unlock()
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	// Atualizar último acesso
	now := time.Now()
	secret.LastAccessed = &now

	secretAccess.WithLabelValues(key, "get", "success").Inc()
	store.mu.Lock()
	store.audit = append(store.audit, AuditLog{
		Key:       key,
		Service:   service,
		Action:    "get",
		Timestamp: now,
		Success:   true,
	})
	store.mu.Unlock()

	// Log SEM expor o valor do segredo
	maskedValue := maskSecret(secret.Value)
	logger.Info("secret_accessed",
		zap.String("key", key),
		zap.String("service", service),
		zap.String("value_masked", maskedValue),
		zap.Int("version", secret.Version),
	)

	span.SetAttributes(
		attribute.String("secret.key", key),
		attribute.String("secret.service", service),
		attribute.Int("secret.version", secret.Version),
	)

	// Retornar segredo (em produção, seria criptografado)
	response := *secret
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleSetSecret(w http.ResponseWriter, r *http.Request) {
	_, span := tracer.Start(r.Context(), "secret.set")
	defer span.End()

	service, authenticated := authenticateService(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	key := r.URL.Path[len("/secrets/"):]
	if key == "" {
		http.Error(w, "Key required", http.StatusBadRequest)
		return
	}

	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	store.mu.Lock()
	existing, exists := store.secrets[key]
	version := 1
	if exists {
		version = existing.Version + 1
	}

	secret := &Secret{
		Key:       key,
		Value:     req.Value,
		Version:   version,
		CreatedAt: time.Now(),
	}

	if exists {
		now := time.Now()
		secret.RotatedAt = &now
		secret.CreatedAt = existing.CreatedAt
	}

	store.secrets[key] = secret
	store.audit = append(store.audit, AuditLog{
		Key:       key,
		Service:   service,
		Action:    "set",
		Timestamp: time.Now(),
		Success:   true,
	})
	store.mu.Unlock()

	secretAccess.WithLabelValues(key, "set", "success").Inc()

	maskedValue := maskSecret(req.Value)
	logger.Info("secret_set",
		zap.String("key", key),
		zap.String("service", service),
		zap.String("value_masked", maskedValue),
		zap.Int("version", version),
	)

	span.SetAttributes(
		attribute.String("secret.key", key),
		attribute.String("secret.service", service),
		attribute.Int("secret.version", version),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secret)
}

func handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	_, span := tracer.Start(r.Context(), "secret.rotate")
	defer span.End()

	service, authenticated := authenticateService(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	key := r.URL.Path[len("/secrets/rotate/"):]
	if key == "" {
		http.Error(w, "Key required", http.StatusBadRequest)
		return
	}

	store.mu.Lock()
	secret, exists := store.secrets[key]
	if !exists {
		store.mu.Unlock()
		secretRotations.WithLabelValues(key, "not_found").Inc()
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	// Gerar novo valor
	newValue := generateRandomSecret(32)
	oldValue := secret.Value

	secret.Value = newValue
	secret.Version++
	now := time.Now()
	secret.RotatedAt = &now

	store.audit = append(store.audit, AuditLog{
		Key:       key,
		Service:   service,
		Action:    "rotate",
		Timestamp: now,
		Success:   true,
	})
	store.mu.Unlock()

	secretRotations.WithLabelValues(key, "success").Inc()

	logger.Info("secret_rotated",
		zap.String("key", key),
		zap.String("service", service),
		zap.String("old_value_masked", maskSecret(oldValue)),
		zap.String("new_value_masked", maskSecret(newValue)),
		zap.Int("version", secret.Version),
	)

	span.SetAttributes(
		attribute.String("secret.key", key),
		attribute.String("secret.service", service),
		attribute.Int("secret.version", secret.Version),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secret)
}

func handleAudit(w http.ResponseWriter, r *http.Request) {
	service, authenticated := authenticateService(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	store.mu.RLock()
	audit := make([]AuditLog, len(store.audit))
	copy(audit, store.audit)
	store.mu.RUnlock()

	// Filtrar por serviço se necessário
	filtered := make([]AuditLog, 0)
	for _, entry := range audit {
		if service == "auth-service" || entry.Service == service {
			filtered = append(filtered, entry)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filtered)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	initLogger()
	defer logger.Sync()

	initTracing()

	// Inicializar alguns segredos de exemplo
	store.mu.Lock()
	store.secrets["database-password"] = &Secret{
		Key:       "database-password",
		Value:     generateRandomSecret(32),
		Version:   1,
		CreatedAt: time.Now(),
	}
	store.secrets["api-key"] = &Secret{
		Key:       "api-key",
		Value:     generateRandomSecret(24),
		Version:   1,
		CreatedAt: time.Now(),
	}
	store.mu.Unlock()

	http.HandleFunc("/secrets/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && !strings.Contains(r.URL.Path, "/rotate/") {
			handleGetSecret(w, r)
		} else if r.Method == "POST" {
			handleSetSecret(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/secrets/rotate/", handleRotateSecret)
	http.HandleFunc("/audit", handleAudit)
	http.HandleFunc("/health", handleHealth)
	http.Handle("/metrics", promhttp.Handler())

	logger.Info("secret-manager ready",
		zap.String("service", "secret-manager"),
		zap.String("version", "1.0.0"),
	)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}
