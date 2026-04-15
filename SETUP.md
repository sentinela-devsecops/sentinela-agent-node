# 🚀 Guia de Setup — Sentinela Agent

> **Responsável:** Gustavo Martins
> **Versão:** 1.0.0
> **Última atualização:** 2026-04-02

---

## 📋 Índice

1. [Pré-requisitos](#pré-requisitos)
2. [Instalação Local](#instalação-local)
3. [Configuração (.env)](#configuração-env)
4. [Registro do Agente](#registro-do-agente)
5. [Rodar Localmente](#rodar-localmente)
6. [Rodar com Docker](#rodar-com-docker)
7. [SLA & Validação](#sla--validação)
8. [Troubleshooting](#troubleshooting)

---

## Pré-requisitos

### Local (Desenvolvimento)

- **Node.js 18 LTS** ou superior
  ```bash
  node --version  # v18.x.x
  npm --version   # 9.x.x ou superior
  ```

### Docker (Produção)

- **Docker 20.10+**
- **Docker Compose 2.0+**
  ```bash
  docker --version
  docker-compose --version
  ```

---

## Instalação Local

### 1. Clone o repositório

```bash
git clone https://github.com/seu-org/sentinela-agent.git
cd sentinela-agent/sentinela-agent
```

### 2. Instale as dependências

```bash
npm install
```

Dependências principais:

- `chokidar ^3.6.0` — FS watch (detecção < 500ms)
- `axios ^1.7.2` — HTTP client
- `dotenv ^16.4.5` — Env vars
- `uuid ^10.0.0` — Request ID
- `node-forge ^1.3.1` — Crypto complementar

### 3. Verifique a instalação

```bash
npm run test
# Output esperado: ✓ Todas as dependências carregadas
```

---

## Configuração (.env)

### 1. Copie o template

```bash
cp .env.example .env
```

### 2. Preencha com valores iniciais (Development)

```bash
# Desenvolvimento local
AGENT_ID=agent-dev-local
AGENT_TOKEN=550e8400-e29b-41d4-a716-446655440000
API_BASE_URL=http://localhost:8080/v1
SERVER_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
...COLAR AQUI...
-----END PUBLIC KEY-----"
HMAC_SECRET=550e8400e29b41d4a716446655440000
WATCH_PATHS=./app,./config,.env
ENVIRONMENT=DEVELOPMENT
LOG_LEVEL=debug
```

### 3. Variáveis Obrigatórias

Certifique-se de que **estas 5 estão preenchidas**:

- ✅ `AGENT_ID` — seu identificador no sistema
- ✅ `AGENT_TOKEN` — UUID único (como senha)
- ✅ `API_BASE_URL` — URL da API
- ✅ `SERVER_PUBLIC_KEY` — chave RSA-4096 do servidor
- ✅ `HMAC_SECRET` — 64 bytes em hex (obtidos com criptografia)

Se alguma estiver vazia, o agente **falha na inicialização**:

```
[Sentinela] ERRO FATAL: Variáveis de ambiente obrigatórias ausentes:
AGENT_ID, AGENT_TOKEN, API_BASE_URL, SERVER_PUBLIC_KEY, HMAC_SECRET
```

### 4. Gerar HMAC_SECRET aleatório

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# Cole a saída em HMAC_SECRET no .env
```

### 5. ⚠️ NUNCA versione o .env real

O arquivo `.env` **está no `.gitignore`** para sua segurança. Seus colegas devem:

```bash
# Cada desenvolvedor:
cp .env.example .env
# e preencher com seus valores
```

---

## Registro do Agente

### Na primeira execução, registre o agente na API

**Endpoint:** `POST /agents/register`

```bash
curl -X POST https://api.sentinela.io/v1/agents/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "agent-prod-backend",
    "environment": "PRODUCTION",
    "hostname": "srv-backend-01",
    "watch_paths": ["/app", "/etc/config", ".env"]
  }'
```

**Resposta esperada (201):**

```json
{
  "agent_id": "agent-prod-backend-a3f9",
  "agent_token": "550e8400-e29b-41d4-a716-446655440000",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "rate_limit": 100,
  "created_at": "2025-01-15T10:00:00Z"
}
```

Copie `agent_id`, `agent_token` e `public_key` para seu `.env`:

```bash
AGENT_ID=agent-prod-backend-a3f9
AGENT_TOKEN=550e8400-e29b-41d4-a716-446655440000
SERVER_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n..."
```

---

## Rodar Localmente

### Terminal 1: Inicie a API Java

```bash
cd ../sentinela-api
./mvnw spring-boot:run
# Esperado: Server started on port 8080
```

### Terminal 2: Inicie o Agente

```bash
npm start
```

**Output esperado:**

```
[Sentinela] ✓ Autenticado com sucesso (JWT obtido)
[Sentinela] ✓ Chokidar iniciado — monitorando: ./app, ./config, .env
[Sentinela] Aguardando mudanças...
```

### Terminal 3: Teste com um arquivo

```bash
# Crie um arquivo com segredo AWS
echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" >> ./config/test.env

# Veja a detecção no agente:
[Sentinela] ✓ Segredo detectado: AWS_ACCESS_KEY_ID
[Sentinela] → Enviando alerta cifrado para API...
[Sentinela] ✓ Alerta 200 (duplicado ignorado — SHA-256 match)
```

---

## Rodar com Docker

### 1. Build da imagem

```bash
docker build -t sentinela-agent:latest .
```

### 2. Verifique o Dockerfile

```dockerfile
FROM node:18-alpine
USER sentinela:1001
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/index.js"]
```

### 3. Execute com docker-compose

Na raiz do projeto:

```bash
docker-compose up -d sentinela-db
# Aguarde: "database system is ready to accept connections"

docker-compose up -d
# Inicia: agente, API Java, React, PostgreSQL
```

### 4. Verifique status

```bash
docker ps
docker logs sentinela-agent

# Esperado:
# [Sentinela] ✓ Autenticado com sucesso
# [Sentinela] ✓ Chokidar iniciado
```

### 5. Parar e remover

```bash
docker-compose down -v
# Remove containers, volumes, networks
```

---

## SLA & Validação

### Health Check

O agente reporta seu status via **GET /agents/{id}/status**:

```bash
curl -H "Authorization: Bearer <jwt>" \
  https://api.sentinela.io/v1/agents/agent-prod-01/status

# Resposta esperada
{
  "agent_id": "agent-prod-01",
  "status": "ONLINE",
  "last_seen": "2025-01-15T10:29:55Z",
  "cpu_usage_pct": 2.3,
  "alerts_sent_today": 17,
  "buffer_pending": 0,
  "watchdog_restarts": 0
}
```

### Requisitos (conforme SLA)

| Métrica                    | Meta         | Status |
| -------------------------- | ------------ | ------ |
| Latência detecção → alerta | < 500ms      | ✓      |
| CPU do agente (repouso)    | < 5%         | ✓      |
| Taxa de falso positivo     | < 2%         | ✓      |
| Taxa de sucesso de envio   | 99.9%        | ✓      |
| JWT refresh automático     | a cada 15min | ✓      |

---

## Troubleshooting

### Erro: "AGENT_ID e AGENT_TOKEN são obrigatórios"

**Solução:**

```bash
# Verifique se .env existe
ls -la .env

# Verifique se as variáveis estão preenchidas
grep -E "^AGENT_" .env

# Se não existir, copie do template
cp .env.example .env
# e preencha corretamente
```

### Erro: "Falha ao conectar com API"

**Solução:**

```bash
# Verifique API_BASE_URL
echo $API_BASE_URL

# Teste conectividade
curl -v https://api.sentinela.io/v1/health

# Se local, verifique se a API Java está rodando
docker ps | grep sentinela-api
```

### Erro: "JWT expirado"

**Normal!** O agente renova automaticamente a cada 15 min. Se vir esta mensagem ocasionalmente, tudo está funcionando.

### Agente detectando muitos falsos positivos

**Ajuste LOG_LEVEL** em `.env`:

```bash
LOG_LEVEL=warn  # Menos verboso
# ou
LOG_LEVEL=debug  # Mais verboso (desenvolvimento)
```

### Buffer cheio (alertas descartados)

**Aumente BUFFER_MAX_SIZE** em `.env`:

```bash
BUFFER_MAX_SIZE=1000  # Padrão: 500
```

---

## 🎯 Checklist de Deploy

- [ ] Node.js 18+ instalado
- [ ] `npm install` executado
- [ ] `.env` copiado de `.env.example`
- [ ] Todas as 5 variáveis obrigatórias preenchidas
- [ ] Agente registrado (`POST /agents/register`)
- [ ] `npm start` sem erros
- [ ] Arquivo de teste criado e detectado
- [ ] Alerta enviado para API (status 200 ou 201)
- [ ] Docker Compose funcionando (opcional)
- [ ] Healthcheck retorna `ONLINE`

---

## 📞 Suporte

Para dúvidas:

- Consulte `README.md`
- Revise `../sentinela-api-docs.html`
- Abra issue no repositório

**Time responsável:** Gustavo Martins (Agente + Docker)
