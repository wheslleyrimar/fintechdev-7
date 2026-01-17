# Conceitos Fundamentais — Segurança Aplicada e Governança

## Zero Trust Architecture

**Princípio**: Nunca confie, sempre verifique.

### Características

- **Identidade antes de rede**: Autenticação é obrigatória, independente da origem
- **Verificação contínua**: Cada requisição é validada
- **Menor privilégio**: Acesso apenas ao necessário
- **Micro-segmentação**: Cada serviço é isolado

### No Código

```go
// Toda requisição precisa de token
func authenticateMiddleware(next http.HandlerFunc) http.HandlerFunc {
    token, err := extractToken(r)
    if err != nil {
        return http.Error(w, "Unauthorized", 401)
    }
    // Validar token...
}
```

---

## Autenticação vs Autorização

### Autenticação: "Quem é você?"

- Verifica identidade
- Usa credenciais (username/password, tokens)
- Resposta: "Você é o usuário X"

### Autorização: "O que você pode fazer?"

- Verifica permissões
- Usa scopes/roles
- Resposta: "Você pode fazer Y, mas não Z"

### Exemplo

```go
// Autenticação: token válido?
token, _ := validateToken(tokenString)

// Autorização: tem permissão?
if !hasScope(claims, "payments:write") {
    return http.Error(w, "Forbidden", 403)
}
```

---

## JWT e OAuth2

### JWT (JSON Web Token)

**Estrutura**: `header.payload.signature`

- **Header**: Algoritmo de assinatura
- **Payload**: Claims (sub, exp, scopes, roles)
- **Signature**: Assinatura criptográfica

### Claims Importantes

- `sub`: Subject (usuário/serviço)
- `exp`: Expiration time
- `scopes`: Permissões (ex: `["payments:read", "payments:write"]`)
- `roles`: Papéis (ex: `["user", "admin"]`)

### OAuth2 Scopes

- `payments:read`: Ler pagamentos
- `payments:write`: Criar pagamentos
- `payments:admin`: Administrar pagamentos
- `secrets:read`: Ler segredos
- `secrets:write`: Escrever segredos

---

## Service-to-Service Security

### Problema

Serviços precisam se comunicar de forma segura.

### Soluções

1. **mTLS**: Mutual TLS (ambos os lados autenticados)
2. **Service Tokens**: Tokens JWT específicos para serviços
3. **API Keys**: Chaves compartilhadas (menos seguro)

### No Código

```go
// Serviço obtém token
serviceToken := getServiceToken("payment-service")

// Usa token para acessar outro serviço
req.Header.Set("Authorization", "Bearer " + serviceToken)
```

---

## Proteção de Dados

### Dados em Trânsito

- **TLS/HTTPS**: Criptografia durante transporte
- **Nunca enviar dados sensíveis em HTTP**

### Dados em Repouso

- **Criptografia AES-256**: Para dados sensíveis
- **Chaves gerenciadas**: Via secret manager
- **Rotação periódica**: Mudar chaves regularmente

### No Código

```go
// Criptografar antes de armazenar
encryptedCPF, _ := encrypt(cpf)

// Descriptografar quando necessário
cpf, _ := decrypt(encryptedCPF)
```

---

## Logs e Segurança

### Problema

Logs podem vazar dados sensíveis.

### Dados que NUNCA devem aparecer em logs

- CPF completo
- Número de cartão completo
- Tokens/JWT completos
- Senhas
- Chaves de API

### Solução: Mascaramento

```go
func maskCPF(cpf string) string {
    return "***.***.***-" + cpf[len(cpf)-2:]
}

func maskCardNumber(card string) string {
    return "****-****-****-" + card[len(card)-4:]
}

// Log seguro
logger.Info("payment",
    zap.String("cpf_masked", maskCPF(cpf)),
    zap.String("card_masked", maskCardNumber(card)),
)
```

### Princípio

**Logue por intenção, não por dados.**

---

## Gestão de Segredos

### Problema

Onde armazenar senhas, chaves, tokens?

### Soluções

1. **Secret Manager**: Serviço centralizado (ex: Vault, AWS Secrets Manager)
2. **Variáveis de ambiente**: Para desenvolvimento apenas
3. **NUNCA**: No código, no repositório, em logs

### Características

- **Rotação automática**: Mudar segredos periodicamente
- **Auditoria**: Registrar todos os acessos
- **Escopo mínimo**: Cada serviço acessa apenas o necessário

### No Código

```go
// Obter segredo do secret manager
secret := getSecret("database-password")

// Rotacionar segredo
rotateSecret("api-key")
```

---

## Governança Técnica

### Objetivo

Escalar times com segurança e consistência.

### Componentes

1. **Padrões mínimos**: Autenticação, logs, métricas
2. **Golden Paths**: Caminhos recomendados
3. **Decisões registradas**: ADRs (Architecture Decision Records)
4. **Exceções conscientes**: Quando desviar, documentar

### Exemplos

- **Padrão de autenticação**: Todos os serviços usam JWT
- **Padrão de logs**: Sempre estruturados, sempre mascarados
- **Padrão de métricas**: RED + métricas de segurança

---

## Compliance como Consequência

### Regulamentações

- **LGPD**: Lei Geral de Proteção de Dados (Brasil)
- **PCI DSS**: Pagamentos com cartão
- **SOX**: Controles financeiros

### Abordagem

**Sistemas bem projetados tendem a ser compliance.**

- Criptografia → LGPD
- Auditoria → SOX
- Segregação de dados → PCI DSS

---

## Anti-patterns

### ❌ Confiar na Rede

```go
// ERRADO: Assumir que rede interna é segura
if r.RemoteAddr == "internal" {
    return true // Sem autenticação!
}
```

### ❌ Permissões Amplas

```go
// ERRADO: Dar todas as permissões
scopes := []string{"*"} // Tudo!
```

### ❌ Logs com Dados Sensíveis

```go
// ERRADO: Logar dados completos
logger.Info("payment", zap.String("cpf", cpf)) // Vazamento!
```

### ❌ Segurança "Depois"

```go
// ERRADO: Adicionar segurança depois
// Primeiro: func handlePayment() { ... }
// Depois: "Ah, vamos adicionar auth..."
```

---

## Boas Práticas

### ✅ Zero Trust

- Toda requisição autenticada
- Service-to-service também autenticado

### ✅ Menor Privilégio

- Scopes mínimos necessários
- Roles específicos

### ✅ Logs Seguros

- Sempre mascarar dados sensíveis
- Logue intenção, não dados

### ✅ Segredos Gerenciados

- Secret manager centralizado
- Rotação automática
- Auditoria completa

### ✅ Segurança desde o Início

- Não é "depois"
- É parte do design

---

## Métricas de Segurança

### O que medir

- **Auth failures**: Tentativas de autenticação falhadas
- **Auth successes**: Autenticações bem-sucedidas
- **Authorization failures**: Falhas de autorização
- **Token validations**: Validações de token
- **Secret access**: Acessos a segredos
- **Secret rotations**: Rotações de segredos

### Por quê?

- Detectar ataques
- Identificar problemas
- Auditoria e compliance

---

## Resumo

1. **Zero Trust**: Nunca confie, sempre verifique
2. **Autenticação ≠ Autorização**: Quem vs O que
3. **JWT + OAuth2**: Tokens com scopes
4. **Service-to-service**: Também precisa de segurança
5. **Criptografia**: Em trânsito e repouso
6. **Logs seguros**: Mascarar dados sensíveis
7. **Secret manager**: Centralizado e auditado
8. **Governança**: Padrões e golden paths

> **"Sistemas seguros não confiam. Sistemas maduros governam."**
