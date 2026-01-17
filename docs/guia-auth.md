# Guia de Autenticação e Autorização

## Visão Geral

Este guia explica como usar o sistema de autenticação e autorização implementado.

---

## Fluxo de Autenticação

### 1. Login

```bash
curl -X POST http://localhost:8083/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user1",
    "password": "password123"
  }'
```

**Resposta**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "payments:read payments:write",
  "roles": ["user"]
}
```

### 2. Usar Token

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -X POST http://localhost:8080/payments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "accountId": "acc-1",
    "amount": 100.50,
    "currency": "BRL"
  }'
```

---

## Usuários Disponíveis

| Username | Password | Roles | Scopes |
|----------|----------|-------|--------|
| `user1` | `password123` | `user` | `payments:read`, `payments:write` |
| `admin` | `admin123` | `admin`, `user` | `payments:read`, `payments:write`, `payments:admin`, `secrets:read`, `secrets:write` |
| `viewer` | `viewer123` | `viewer` | `payments:read` |

---

## Scopes e Permissões

### Scopes de Pagamento

- `payments:read`: Ler informações de pagamentos
- `payments:write`: Criar pagamentos
- `payments:admin`: Administrar pagamentos

### Scopes de Segredos

- `secrets:read`: Ler segredos do secret manager
- `secrets:write`: Criar/atualizar segredos

### Scopes de Autenticação

- `auth:admin`: Administrar autenticação

---

## Service-to-Service Tokens

### Obter Token para Serviço

```bash
curl -X POST http://localhost:8083/auth/service-token \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "service_name": "payment-service"
  }'
```

### Serviços Autorizados

- `payment-service`
- `antifraud-service`
- `notification-service`
- `auth-service`

---

## Validação de Token

### Validar Token

```bash
curl -X POST http://localhost:8083/auth/validate \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

**Resposta**:
```json
{
  "valid": true,
  "claims": {
    "sub": "user1",
    "exp": 1234567890,
    "scopes": ["payments:read", "payments:write"],
    "roles": ["user"]
  },
  "expires": "2024-01-15T10:30:00Z"
}
```

---

## Troubleshooting

### Erro: "Unauthorized: missing authorization header"

**Causa**: Token não foi enviado.

**Solução**: Adicione o header `Authorization: Bearer <token>`

### Erro: "Unauthorized: invalid token"

**Causa**: Token inválido ou expirado.

**Solução**: 
1. Verifique se o token está completo
2. Faça login novamente para obter novo token

### Erro: "Forbidden: insufficient permissions"

**Causa**: Token válido, mas sem permissões necessárias.

**Solução**: 
1. Verifique os scopes do token
2. Use um usuário com permissões adequadas
3. Ou solicite permissões adicionais

### Erro: "Unauthorized: token expired"

**Causa**: Token expirou (padrão: 1 hora).

**Solução**: Faça login novamente para obter novo token.

---

## Boas Práticas

### 1. Nunca Expor Tokens em Logs

```go
// ❌ ERRADO
logger.Info("token", zap.String("token", token))

// ✅ CORRETO
logger.Info("token", zap.String("token_masked", maskToken(token)))
```

### 2. Validar Token em Cada Requisição

Não cachear validação de token por muito tempo.

### 3. Usar HTTPS em Produção

Sempre usar HTTPS para proteger tokens em trânsito.

### 4. Tokens de Curta Duração

Tokens devem expirar rapidamente (ex: 1 hora).

### 5. Rotação de Tokens

Implementar refresh tokens para renovar sem login.

---

## Exemplos Completos

### Exemplo 1: Fluxo Completo

```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:8083/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password123"}' | jq -r '.access_token')

# 2. Criar pagamento
curl -X POST http://localhost:8080/payments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "accountId": "acc-1",
    "amount": 100.50,
    "currency": "BRL"
  }'

# 3. Validar token
curl -X POST http://localhost:8083/auth/validate \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}"
```

### Exemplo 2: Service-to-Service

```bash
# 1. Obter token de serviço
SERVICE_TOKEN=$(curl -s -X POST http://localhost:8083/auth/service-token \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"service_name":"payment-service"}' | jq -r '.access_token')

# 2. Usar token para acessar secret manager
curl -X GET http://localhost:8084/secrets/database-password \
  -H "Authorization: Bearer $SERVICE_TOKEN"
```

---

## Segurança

### Tokens JWT

- **Algoritmo**: HS256
- **Expiração**: 1 hora (configurável)
- **Claims**: sub, exp, scopes, roles, type

### Validação

- Assinatura verificada
- Expiração verificada
- Claims validados

### Mascaramento

- Tokens nunca aparecem completos em logs
- Apenas prefixo e sufixo são mostrados

---

**Para mais informações, consulte [conceitos.md](conceitos.md)**
