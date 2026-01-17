# Aula 7 — Segurança Aplicada e Governança

## 📚 Índice

1. [Visão Geral](#visão-geral)
2. [Como Executar](#como-executar)
3. [Conceitos Implementados](#conceitos-implementados)
4. [Documentação Completa](#documentação-completa)
5. [Endpoints Disponíveis](#endpoints-disponíveis)
6. [Exercícios Práticos](#exercícios-práticos)
7. [Checklist de Segurança](#checklist-de-segurança)

---

## Visão Geral

Este projeto demonstra **segurança aplicada e governança** em sistemas distribuídos, implementando:

- ✅ **Zero Trust**: Autenticação e autorização em todas as comunicações
- ✅ **JWT e OAuth2**: Tokens de curta duração com scopes e claims
- ✅ **Service-to-service security**: Tokens para comunicação entre serviços
- ✅ **Proteção de dados**: Criptografia em trânsito (TLS) e em repouso
- ✅ **Mascaramento de logs**: Dados sensíveis nunca aparecem em logs
- ✅ **Gestão de segredos**: Secret manager com rotação automática
- ✅ **Governança técnica**: Padrões e golden paths

### Stack Tecnológica

- **Go 1.22**: Serviços de alta performance
- **JWT**: Autenticação baseada em tokens
- **Vault** (simulado): Gestão de segredos
- **Prometheus**: Métricas de segurança
- **Grafana**: Visualização de métricas
- **Jaeger**: Distributed tracing (com dados mascarados)
- **RabbitMQ**: Message broker (com autenticação)
- **Docker Compose**: Orquestração

---

## Como Executar

### Pré-requisitos

- Docker e Docker Compose instalados
- Portas disponíveis: 8080, 8081, 8082, 8083, 5672, 15672, 9090, 3000, 16686

### Passo 1: Subir o Ambiente

```bash
cd "/Users/wheslley/Desktop/Fintech Dev/Aula 7/fintechdev-7"
docker compose up --build
```

### Passo 2: Aguardar Inicialização

Aguarde até ver nos logs:
```
auth-service         | auth-service listening on :8083
payment-service      | payment-service listening on :8080
antifraud-service    | antifraud-service ready
notification-service | notification-service ready
secret-manager       | secret-manager ready
```

### Passo 3: Obter Token de Acesso

```bash
# Obter token para usuário comum
curl -X POST http://localhost:8083/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user1",
    "password": "password123"
  }'
```

Resposta esperada:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "payments:read payments:write"
}
```

### Passo 4: Fazer Requisição Autenticada

```bash
# Usar o token obtido
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

## Conceitos Implementados

### 🔐 Autenticação vs Autorização

- **Autenticação**: Quem é você? (JWT com claims)
- **Autorização**: O que você pode fazer? (Scopes e roles)

### 🛡️ Zero Trust

- Nenhuma comunicação é confiável por padrão
- Toda requisição precisa de token válido
- Service-to-service também requer autenticação

### 🔒 Proteção de Dados

- **Em trânsito**: TLS/HTTPS (simulado)
- **Em repouso**: Criptografia AES-256
- **Em logs**: Mascaramento automático

### 📝 Logs Seguros

- Dados sensíveis nunca aparecem em logs
- CPF, cartão, tokens são mascarados
- Logs por intenção, não por dados

### 🔑 Gestão de Segredos

- Secret manager centralizado
- Rotação automática de chaves
- Auditoria de acesso

---

## Documentação Completa

A documentação completa está organizada em documentos separados:

### 📖 Conceitos Fundamentais
**[docs/conceitos.md](docs/conceitos.md)**
- Zero Trust Architecture
- Autenticação vs Autorização
- JWT e OAuth2
- Service-to-service security
- Proteção de dados (criptografia)
- Logs e segurança
- Gestão de segredos
- Governança técnica

### 🏗️ Arquitetura do Sistema
**[docs/arquitetura.md](docs/arquitetura.md)**
- Diagrama de arquitetura com segurança
- Fluxo de autenticação
- Fluxo de autorização
- Service-to-service communication
- Secret management flow

### 🔐 Guia de Autenticação e Autorização
**[docs/guia-auth.md](docs/guia-auth.md)**
- Como obter tokens
- Como usar tokens
- Scopes e permissões
- Service-to-service tokens
- Troubleshooting

### 🔒 Guia de Proteção de Dados
**[docs/guia-protecao-dados.md](docs/guia-protecao-dados.md)**
- Criptografia em trânsito
- Criptografia em repouso
- Mascaramento de logs
- Boas práticas

### 🔑 Gestão de Segredos
**[docs/guia-segredos.md](docs/guia-segredos.md)**
- Como usar o secret manager
- Rotação de chaves
- Auditoria
- Boas práticas

### 🛡️ Anti-patterns e Boas Práticas
**[docs/anti-patterns.md](docs/anti-patterns.md)**
- Erros comuns de segurança
- O que NÃO fazer
- Como corrigir problemas

---

## Endpoints Disponíveis

### Auth Service (porta 8083)

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| `POST` | `/auth/login` | Login e obter token | Não |
| `POST` | `/auth/validate` | Validar token | Não |
| `POST` | `/auth/service-token` | Obter token service-to-service | Token de serviço |
| `GET` | `/health` | Health check | Não |

### Payment Service (porta 8080)

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| `POST` | `/payments` | Criar pagamento | **Sim** (Bearer token) |
| `GET` | `/health` | Health check | Não |
| `GET` | `/metrics` | Métricas Prometheus | Não |

### Secret Manager (porta 8084)

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| `GET` | `/secrets/:key` | Obter segredo | Token de serviço |
| `POST` | `/secrets/:key` | Criar/atualizar segredo | Token de serviço |
| `GET` | `/secrets/rotate/:key` | Rotacionar segredo | Token de serviço |
| `GET` | `/audit` | Auditoria de acesso | Token de serviço |

---

## Exercícios Práticos

### Exercício 1: Autenticação Básica
**Objetivo**: Entender autenticação vs autorização

1. Faça login como usuário comum
2. Tente criar um pagamento
3. Faça login como admin
4. Compare as permissões

**Verificar**: Logs mostram diferentes scopes?

### Exercício 2: Service-to-Service Security
**Objetivo**: Entender comunicação segura entre serviços

1. Obtenha um token service-to-service
2. Use o token para acessar o secret manager
3. Verifique os logs: o token aparece mascarado?

**Verificar**: Logs não expõem tokens?

### Exercício 3: Mascaramento de Dados
**Objetivo**: Ver como dados sensíveis são protegidos em logs

1. Crie um pagamento com dados sensíveis (CPF, cartão)
2. Verifique os logs do payment-service
3. Compare: dados aparecem mascarados?

**Verificar**: CPF e cartão aparecem como `***`?

### Exercício 4: Gestão de Segredos
**Objetivo**: Entender rotação e auditoria

1. Obtenha um segredo do secret manager
2. Rotacione o segredo
3. Verifique a auditoria
4. Tente usar o segredo antigo (deve falhar)

**Verificar**: Rotação funciona? Auditoria registra acesso?

### Exercício 5: Zero Trust Violation
**Objetivo**: Ver o que acontece sem autenticação

1. Tente criar pagamento sem token
2. Tente criar pagamento com token inválido
3. Tente criar pagamento com token expirado
4. Verifique métricas de segurança

**Verificar**: Todas as tentativas são bloqueadas?

### Exercício 6: Criptografia de Dados
**Objetivo**: Ver dados criptografados

1. Crie um pagamento
2. Verifique como os dados são armazenados (simulado)
3. Compare dados em trânsito vs repouso

**Verificar**: Dados sensíveis estão criptografados?

---

## Checklist de Segurança

### ✅ Autenticação
- [ ] Todas as requisições requerem token?
- [ ] Tokens têm expiração curta?
- [ ] Service-to-service usa tokens?

### ✅ Autorização
- [ ] Scopes são verificados?
- [ ] Roles são respeitados?
- [ ] Princípio do menor privilégio?

### ✅ Proteção de Dados
- [ ] Dados sensíveis criptografados?
- [ ] Logs não expõem dados sensíveis?
- [ ] TLS em todas as comunicações?

### ✅ Gestão de Segredos
- [ ] Segredos não estão no código?
- [ ] Rotação automática funciona?
- [ ] Auditoria registra acessos?

### ✅ Observabilidade Segura
- [ ] Logs mascarados?
- [ ] Métricas não expõem dados?
- [ ] Traces não contêm segredos?

---

## Suporte

Em caso de dúvidas:

1. Verifique logs: `docker compose logs -f [service-name]`
2. Verifique métricas: http://localhost:9090
3. Verifique traces: http://localhost:16686
4. Consulte a [documentação completa](#documentação-completa)

---

**Desenvolvido para demonstrar segurança aplicada e governança em sistemas distribuídos.**

> **"Sistemas seguros não confiam. Sistemas maduros governam."**
