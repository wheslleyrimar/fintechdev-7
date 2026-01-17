package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

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

var (
	logger *zap.Logger
	tracer trace.Tracer

	notificationsSent = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "notifications_sent_total",
			Help: "Total notifications sent",
		},
		[]string{"channel", "status"},
	)

	notificationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "notification_duration_seconds",
			Help:    "Notification sending duration",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
		},
		[]string{"channel"},
	)

	notificationErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "notification_errors_total",
			Help: "Total notification errors",
		},
		[]string{"channel", "error_type"},
	)
)

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
			semconv.ServiceName("notification-service"),
		)),
		tracesdk.WithSampler(tracesdk.TraceIDRatioBased(0.02)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer = otel.Tracer("notification-service")
}

func initLogger() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		panic(err)
	}
}

func extractTraceContext(headers amqp.Table) context.Context {
	ctx := context.Background()
	propagator := otel.GetTextMapPropagator()

	carrier := make(map[string]string)
	if headers != nil {
		if traceID, ok := headers["X-Trace-ID"].(string); ok {
			carrier["traceparent"] = traceID
		}
		if correlationID, ok := headers["X-Correlation-ID"].(string); ok {
			carrier["baggage-correlation-id"] = correlationID
		}
	}

	ctx = propagator.Extract(ctx, propagation.MapCarrier(carrier))
	return ctx
}

func sendNotification(ctx context.Context, channel string, paymentID string, amount float64, correlationID, traceID string) error {
	start := time.Now()
	ctx, span := tracer.Start(ctx, fmt.Sprintf("notification.send.%s", channel))
	defer span.End()

	span.SetAttributes(attribute.String("notification.channel", channel))

	baseDelay := 50 * time.Millisecond
	if rand.Float64() < 0.02 {
		baseDelay += 1 * time.Second
		span.RecordError(fmt.Errorf("slow notification: %v", baseDelay))
	}
	time.Sleep(baseDelay)

	if rand.Float64() < 0.05 {
		err := fmt.Errorf("notification service unavailable")
		span.RecordError(err)
		notificationErrors.WithLabelValues(channel, "service_unavailable").Inc()
		notificationsSent.WithLabelValues(channel, "error").Inc()
		return err
	}

	duration := time.Since(start)
	notificationDuration.WithLabelValues(channel).Observe(duration.Seconds())
	notificationsSent.WithLabelValues(channel, "success").Inc()

	// Log seguro: sem dados sensíveis
	logger.Info("notification_sent",
		zap.String("service", "notification-service"),
		zap.String("channel", channel),
		zap.String("payment_id", paymentID),
		zap.Float64("amount", amount),
		zap.Duration("duration_ms", duration),
		zap.String("correlation_id", correlationID),
		zap.String("trace_id", traceID),
		// NUNCA logar: email completo, telefone completo, tokens
	)

	return nil
}

func processPayment(ctx context.Context, msgBody []byte, headers amqp.Table) {
	correlationID := ""
	traceID := ""
	if headers != nil {
		if cid, ok := headers["X-Correlation-ID"].(string); ok {
			correlationID = cid
		}
		if tid, ok := headers["X-Trace-ID"].(string); ok {
			traceID = tid
		}
	}

	ctx, span := tracer.Start(ctx, "notification.process")
	defer span.End()

	var event map[string]interface{}
	if err := json.Unmarshal(msgBody, &event); err != nil {
		logger.Error("failed_to_unmarshal",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
			zap.String("trace_id", traceID),
		)
		return
	}

	paymentID, _ := event["paymentId"].(string)
	amount, _ := event["amount"].(float64)

	// IMPORTANTE: Eventos não devem conter dados sensíveis
	// Se contiverem, não logamos

	channels := []string{"email", "sms", "push", "webhook"}
	for _, channel := range channels {
		go func(ch string) {
			_ = sendNotification(ctx, ch, paymentID, amount, correlationID, traceID)
		}(channel)
	}
}

func main() {
	initLogger()
	defer logger.Sync()

	initTracing()

	rabbitURL := os.Getenv("RABBIT_URL")
	if rabbitURL == "" {
		rabbitURL = "amqp://guest:guest@rabbitmq:5672/"
	}

	conn, err := amqp.Dial(rabbitURL)
	if err != nil {
		logger.Fatal("failed_to_connect_rabbitmq", zap.Error(err))
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		logger.Fatal("failed_to_open_channel", zap.Error(err))
	}
	defer ch.Close()

	ch.ExchangeDeclare("payments", "fanout", true, false, false, false, nil)

	q, err := ch.QueueDeclare("", false, true, true, false, nil)
	if err != nil {
		logger.Fatal("failed_to_declare_queue", zap.Error(err))
	}

	ch.QueueBind(q.Name, "", "payments", false, nil)

	msgs, err := ch.Consume(q.Name, "", true, false, false, false, nil)
	if err != nil {
		logger.Fatal("failed_to_register_consumer", zap.Error(err))
	}

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe(":8080", nil)
	}()

	logger.Info("notification-service ready",
		zap.String("service", "notification-service"),
		zap.String("version", "1.0.0"),
	)

	for msg := range msgs {
		ctx := extractTraceContext(msg.Headers)
		processPayment(ctx, msg.Body, msg.Headers)
	}
}
