# Quick Start — Aula 7

## Início Rápido

### 1. Subir o ambiente

```bash
cd "/Users/wheslley/Desktop/Fintech Dev/Aula 7/fintechdev-7"
docker compose up --build
```

### 2. Aguardar inicialização

Aguarde até ver:
```
auth-service         | auth-service listening on :8080
payment-service      | payment-service listening on :8080
secret-manager       | secret-manager ready
```

### 3. Obter token

```bash
TOKEN=$(curl -s -X POST http://localhost:8083/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password123"}' | jq -r '.access_token')
```

### 4. Criar pagamento

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

### 5. Verificar logs (dados mascarados)

```bash
docker compose logs payment-service | grep "payment_processed" | tail -1
```

---

## Usuários de Teste

| Username | Password | Permissões |
|----------|----------|------------|
| `user1` | `password123` | Criar pagamentos |
| `admin` | `admin123` | Tudo |
| `viewer` | `viewer123` | Apenas leitura |

---

## Endpoints Principais

### Auth Service (8083)

- `POST /auth/login` - Login
- `POST /auth/validate` - Validar token
- `POST /auth/service-token` - Token service-to-service

### Payment Service (8080)

- `POST /payments` - Criar pagamento (requer autenticação)
- `GET /health` - Health check
- `GET /metrics` - Métricas Prometheus

### Secret Manager (8084)

- `GET /secrets/:key` - Obter segredo
- `POST /secrets/:key` - Criar/atualizar segredo
- `GET /secrets/rotate/:key` - Rotacionar segredo
- `GET /audit` - Auditoria

---

## Conceitos Demonstrados

✅ **Zero Trust**: Toda requisição autenticada  
✅ **Autenticação vs Autorização**: Quem vs O que  
✅ **JWT + OAuth2**: Tokens com scopes  
✅ **Service-to-Service**: Tokens para serviços  
✅ **Criptografia**: Dados em trânsito e repouso  
✅ **Mascaramento**: Logs seguros  
✅ **Secret Manager**: Gestão centralizada  
✅ **Governança**: Padrões e golden paths  

---

## Próximos Passos

1. Leia [README.md](README.md) para visão geral
2. Veja [docs/conceitos.md](docs/conceitos.md) para conceitos
3. Faça [docs/exercicios.md](docs/exercicios.md) para prática
4. Explore [docs/arquitetura.md](docs/arquitetura.md) para arquitetura

---

**"Sistemas seguros não confiam. Sistemas maduros governam."**
