# Exercícios Práticos — Segurança Aplicada e Governança

## Exercício 1: Autenticação Básica

**Objetivo**: Entender autenticação vs autorização

### Passo 1: Fazer login como usuário comum

```bash
curl -X POST http://localhost:8083/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user1",
    "password": "password123"
  }'
```

**Salve o token** da resposta em uma variável:

```bash
TOKEN=$(curl -s -X POST http://localhost:8083/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password123"}' | jq -r '.access_token')
```

### Passo 2: Tentar criar pagamento

```bash
curl -X POST http://localhost:8080/payments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "accountId": "acc-1",
    "amount": 100.50,
    "currency": "BRL"
  }'
```

**Verificar**: Deve funcionar? Por quê?

### Passo 3: Fazer login como admin

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8083/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.access_token')
```

### Passo 4: Comparar scopes

```bash
# Ver scopes do user1
echo $TOKEN | cut -d. -f2 | base64 -d | jq '.scopes'

# Ver scopes do admin
echo $ADMIN_TOKEN | cut -d. -f2 | base64 -d | jq '.scopes'
```

**Pergunta**: Qual a diferença? Por que admin tem mais scopes?

### Passo 5: Verificar logs

```bash
docker compose logs payment-service | grep "auth"
```

**Verificar**: Os tokens aparecem completos ou mascarados?

---

## Exercício 2: Service-to-Service Security

**Objetivo**: Entender comunicação segura entre serviços

### Passo 1: Obter token service-to-service

```bash
SERVICE_TOKEN=$(curl -s -X POST http://localhost:8083/auth/service-token \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"service_name":"payment-service"}' | jq -r '.access_token')
```

### Passo 2: Usar token para acessar secret manager

```bash
curl -X GET http://localhost:8084/secrets/database-password \
  -H "Authorization: Bearer $SERVICE_TOKEN"
```

**Verificar**: Funciona? Por quê?

### Passo 3: Verificar logs

```bash
docker compose logs secret-manager | grep "secret_accessed"
```

**Verificar**: O valor do segredo aparece nos logs? Deve aparecer?

### Passo 4: Tentar acessar sem token

```bash
curl -X GET http://localhost:8084/secrets/database-password
```

**Verificar**: O que acontece? Por quê?

---

## Exercício 3: Mascaramento de Dados

**Objetivo**: Ver como dados sensíveis são protegidos em logs

### Passo 1: Criar pagamento com dados sensíveis

```bash
curl -X POST http://localhost:8080/payments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "accountId": "acc-1",
    "amount": 100.50,
    "currency": "BRL",
    "cpf": "12345678901",
    "cardNumber": "4111111111111111"
  }'
```

### Passo 2: Verificar logs do payment-service

```bash
docker compose logs payment-service | grep "payment_processed" | tail -1 | jq
```

**Verificar**: 
- CPF aparece completo ou mascarado?
- Cartão aparece completo ou mascarado?
- Como aparecem?

### Passo 3: Verificar traces no Jaeger

1. Acesse http://localhost:16686
2. Busque por traces do payment-service
3. Veja os atributos do span

**Verificar**: Dados sensíveis aparecem nos traces?

---

## Exercício 4: Gestão de Segredos

**Objetivo**: Entender rotação e auditoria

### Passo 1: Obter segredo

```bash
SECRET=$(curl -s -X GET http://localhost:8084/secrets/database-password \
  -H "Authorization: Bearer $SERVICE_TOKEN" | jq -r '.value')

echo "Segredo atual: $SECRET"
```

### Passo 2: Rotacionar segredo

```bash
curl -X GET http://localhost:8084/secrets/rotate/database-password \
  -H "Authorization: Bearer $SERVICE_TOKEN"
```

### Passo 3: Obter novo segredo

```bash
NEW_SECRET=$(curl -s -X GET http://localhost:8084/secrets/database-password \
  -H "Authorization: Bearer $SERVICE_TOKEN" | jq -r '.value')

echo "Novo segredo: $NEW_SECRET"
```

**Verificar**: O segredo mudou? Por quê?

### Passo 4: Verificar auditoria

```bash
curl -s -X GET http://localhost:8084/audit \
  -H "Authorization: Bearer $SERVICE_TOKEN" | jq '.[-5:]'
```

**Verificar**: 
- Quantos acessos foram registrados?
- Quais serviços acessaram?
- Quando?

### Passo 5: Verificar logs

```bash
docker compose logs secret-manager | grep "secret_rotated"
```

**Verificar**: O valor antigo e novo aparecem completos ou mascarados?

---

## Exercício 5: Zero Trust Violation

**Objetivo**: Ver o que acontece sem autenticação

### Passo 1: Tentar criar pagamento sem token

```bash
curl -X POST http://localhost:8080/payments \
  -H "Content-Type: application/json" \
  -d '{
    "accountId": "acc-1",
    "amount": 100.50,
    "currency": "BRL"
  }'
```

**Verificar**: O que acontece? Status code?

### Passo 2: Tentar com token inválido

```bash
curl -X POST http://localhost:8080/payments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token-invalido-123" \
  -d '{
    "accountId": "acc-1",
    "amount": 100.50,
    "currency": "BRL"
  }'
```

**Verificar**: O que acontece?

### Passo 3: Verificar métricas de segurança

```bash
curl -s http://localhost:8080/metrics | grep "auth_failures"
```

**Verificar**: Quantas falhas foram registradas?

### Passo 4: Tentar com token expirado (simulado)

```bash
# Criar token com expiração no passado (não funciona na prática, mas para demonstração)
# O sistema valida exp automaticamente
```

**Verificar**: Como o sistema detecta tokens expirados?

---

## Exercício 6: Autorização (Scopes)

**Objetivo**: Entender diferença entre autenticação e autorização

### Passo 1: Login como viewer (apenas leitura)

```bash
VIEWER_TOKEN=$(curl -s -X POST http://localhost:8083/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"viewer","password":"viewer123"}' | jq -r '.access_token')
```

### Passo 2: Verificar scopes do viewer

```bash
echo $VIEWER_TOKEN | cut -d. -f2 | base64 -d | jq '.scopes'
```

**Verificar**: Quais scopes o viewer tem?

### Passo 3: Tentar criar pagamento com viewer

```bash
curl -X POST http://localhost:8080/payments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $VIEWER_TOKEN" \
  -d '{
    "accountId": "acc-1",
    "amount": 100.50,
    "currency": "BRL"
  }'
```

**Verificar**: Funciona? Por quê não?

### Passo 4: Verificar logs

```bash
docker compose logs payment-service | grep "authorization_failed"
```

**Verificar**: O que aparece nos logs?

### Passo 5: Verificar métricas

```bash
curl -s http://localhost:8080/metrics | grep "authorization_failures"
```

---

## Exercício 7: Criptografia de Dados

**Objetivo**: Ver dados criptografados

### Passo 1: Criar pagamento com dados sensíveis

```bash
curl -X POST http://localhost:8080/payments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "accountId": "acc-1",
    "amount": 100.50,
    "currency": "BRL",
    "cpf": "12345678901",
    "cardNumber": "4111111111111111"
  }'
```

### Passo 2: Verificar como dados são armazenados

**Nota**: No código, os dados são criptografados antes de armazenar (simulado).

**Verificar**: 
- CPF é criptografado antes de armazenar?
- Cartão é criptografado antes de armazenar?
- Como aparecem no código?

### Passo 3: Comparar dados em trânsito vs repouso

**Em trânsito**: 
- Dados são enviados via HTTP (em produção seria HTTPS)
- Mas são mascarados nos logs

**Em repouso**:
- Dados são criptografados antes de armazenar
- Chave de criptografia vem do secret manager (em produção)

---

## Exercício 8: Observabilidade Segura

**Objetivo**: Verificar que observabilidade não expõe dados sensíveis

### Passo 1: Criar alguns pagamentos

```bash
for i in {1..5}; do
  curl -X POST http://localhost:8080/payments \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
      \"accountId\": \"acc-$i\",
      \"amount\": $((100 + i * 10)),
      \"currency\": \"BRL\",
      \"cpf\": \"1234567890$i\",
      \"cardNumber\": \"411111111111111$i\"
    }"
  sleep 1
done
```

### Passo 2: Verificar logs

```bash
docker compose logs payment-service | grep "payment_processed" | tail -5
```

**Verificar**: Dados sensíveis aparecem?

### Passo 3: Verificar métricas no Prometheus

1. Acesse http://localhost:9090
2. Busque por `payments_processed_total`
3. Veja os labels

**Verificar**: Métricas contêm dados sensíveis?

### Passo 4: Verificar traces no Jaeger

1. Acesse http://localhost:16686
2. Busque por traces do payment-service
3. Veja os atributos dos spans

**Verificar**: Traces contêm dados sensíveis?

---

## Exercício 9: Análise de Segurança

**Objetivo**: Analisar métricas de segurança

### Passo 1: Gerar algumas tentativas de autenticação

```bash
# Tentativas válidas
for i in {1..3}; do
  curl -s -X POST http://localhost:8083/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"user1","password":"password123"}' > /dev/null
done

# Tentativas inválidas
for i in {1..5}; do
  curl -s -X POST http://localhost:8083/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"user1","password":"wrong"}' > /dev/null
done
```

### Passo 2: Verificar métricas

```bash
curl -s http://localhost:8083/metrics | grep "auth_"
```

**Verificar**: 
- Quantas tentativas de sucesso?
- Quantas falhas?
- Qual o motivo das falhas?

### Passo 3: Visualizar no Grafana

1. Acesse http://localhost:3000 (admin/admin)
2. Crie um dashboard com métricas de segurança
3. Adicione gráficos para:
   - `auth_attempts_total`
   - `auth_failures_total`
   - `auth_success_total`

---

## Exercício 10: Secret Manager - Rotação

**Objetivo**: Entender rotação automática de segredos

### Passo 1: Criar um segredo

```bash
curl -X POST http://localhost:8084/secrets/api-key \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -d '{"value":"minha-chave-secreta-123"}'
```

### Passo 2: Obter o segredo

```bash
curl -s -X GET http://localhost:8084/secrets/api-key \
  -H "Authorization: Bearer $SERVICE_TOKEN" | jq
```

**Verificar**: Versão do segredo?

### Passo 3: Rotacionar

```bash
curl -X GET http://localhost:8084/secrets/rotate/api-key \
  -H "Authorization: Bearer $SERVICE_TOKEN"
```

### Passo 4: Verificar nova versão

```bash
curl -s -X GET http://localhost:8084/secrets/api-key \
  -H "Authorization: Bearer $SERVICE_TOKEN" | jq '.version'
```

**Verificar**: Versão aumentou?

### Passo 5: Verificar auditoria

```bash
curl -s -X GET http://localhost:8084/audit \
  -H "Authorization: Bearer $SERVICE_TOKEN" | jq '.[] | select(.key == "api-key")'
```

---

## Checklist Final

Após completar todos os exercícios, verifique:

- [ ] Entendi a diferença entre autenticação e autorização
- [ ] Sei como usar tokens JWT
- [ ] Entendo service-to-service security
- [ ] Vejo como dados sensíveis são mascarados
- [ ] Entendo gestão de segredos
- [ ] Sei verificar métricas de segurança
- [ ] Entendo Zero Trust na prática

---

## Desafios Extras

### Desafio 1: Implementar Rate Limiting por Usuário

Adicione rate limiting que limita requisições por usuário (não apenas global).

### Desafio 2: Adicionar Refresh Tokens

Implemente refresh tokens para renovar access tokens sem fazer login novamente.

### Desafio 3: Implementar MFA (Multi-Factor Authentication)

Adicione autenticação de dois fatores.

### Desafio 4: Adicionar Auditoria Completa

Registre todas as ações importantes (criação de pagamento, acesso a segredos, etc.) em um sistema de auditoria.

---

**Bons estudos! 🛡️**
