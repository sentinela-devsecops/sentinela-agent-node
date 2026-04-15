# 🟢 Sentinela Agent — Node.js 18 LTS

> **Responsável:** Gustavo Martins
> **Linguagem:** Node.js 18 LTS (ESM — `"type": "module"`)
> **Projeto:** Sentinela DevSecOps — Camada Agente + Infraestrutura Docker

---

## 📋 Índice

1. [O que é o Sentinela?](#1-o-que-é-o-sentinela)
2. [O que cabe ao Gustavo Martins](#2-o-que-cabe-ao-gustavo-martins)
3. [Arquitetura geral do projeto](#3-arquitetura-geral-do-projeto)
4. [Estrutura de arquivos do agente](#4-estrutura-de-arquivos-do-agente)
5. [Como funciona — fluxo completo](#5-como-funciona--fluxo-completo)
6. [Pipeline de segurança (passo a passo)](#6-pipeline-de-segurança-passo-a-passo)
7. [Configuração e variáveis de ambiente](#7-configuração-e-variáveis-de-ambiente)
8. [Como rodar localmente](#8-como-rodar-localmente)
9. [Como rodar com Docker](#9-como-rodar-com-docker)
10. [Módulos implementados](#10-módulos-implementados)
11. [Regras de detecção (Rules)](#11-regras-de-detecção-rules)
12. [Criptografia RSA-4096 + HMAC-SHA256](#12-criptografia-rsa-4096--hmac-sha256)
13. [Data Masking — regra de ouro](#13-data-masking--regra-de-ouro)
14. [Resiliência e Backoff Exponencial](#14-resiliência-e-backoff-exponencial)
15. [Infraestrutura Docker (também Gustavo)](#15-infraestrutura-docker-também-gustavo)
16. [SLA e Requisitos de Desempenho](#16-sla-e-requisitos-de-desempenho)
17. [Requisitos Funcionais atendidos](#17-requisitos-funcionais-atendidos)
18. [Divisão de responsabilidades do time](#18-divisão-de-responsabilidades-do-time)
19. [Regras e restrições importantes](#19-regras-e-restrições-importantes)
20. [Dependências](#20-dependências)

---

## 1. O que é o Sentinela?

O **Sentinela** é uma plataforma DevSecOps de monitoramento de segurança que detecta segredos expostos (chaves AWS, tokens GitHub, senhas em `.env`, etc.) em sistemas de arquivos e repositórios em tempo real.

O sistema é composto por **4 camadas** desenvolvidas por membros distintos do time:

| Camada | Tecnologia | Responsável |
|---|---|---|
| 🟢 **Agente** | Node.js 18 LTS | **Gustavo Martins** |
| 🔵 **Servidor/API** | Java 17 + Spring Boot 3 | Isadora Lyra |
| 🟣 **Frontend** | React + Vite | João Paulo |
| 🟡 **Infraestrutura Docker** | Docker Compose | **Gustavo Martins** |

---

## 2. O que cabe ao (Gustavo Martins)

### 🟢 Camada Agente — Node.js 18 LTS

Todos os módulos do agente que roda nos sistemas monitorados:

| Módulo | Arquivo | Descrição |
|---|---|---|
| **Entry Point / Watcher** | `src/index.js` | Inicialização, Chokidar, watchdog, graceful shutdown |
| **Scanner Engine** | `src/scanner/index.js` | Leitura de arquivos, Stream API para arquivos grandes |
| **Regex Engine** | `src/rules/index.js` | Regras de detecção (integração — padrões definidos por Caio & André) |
| **Data Masking** | `src/masking/index.js` | Mascaramento de segredos antes de qualquer envio/log |
| **Cifrador RSA-4096** | `src/crypto/index.js` | Cifragem com chave pública do servidor |
| **Assinatura HMAC** | `src/crypto/index.js` | HMAC-SHA256 do payload para integridade |
| **Buffer + Watchdog** | `src/buffer/index.js` | Armazenamento local + backoff exponencial |
| **Transporte HTTP** | `src/transport/index.js` | Comunicação com a API Java (auth, envio, retry) |
| **Logger Seguro** | `src/config/logger.js` | Logs que nunca imprimem segredos |

### 🟡 Infraestrutura Docker

| Arquivo | Descrição |
|---|---|
| `Dockerfile` | Container do agente (Alpine, non-root) |
| `docker-compose.yml` | Stack completa com redes isoladas |

> **Importante:** O (Node.js) **não implementa** a lógica do servidor Java, do frontend React nem as regras regex em si (essas são de Caio & André). Ele consome as regras e integra tudo no agente.

---

## 3. Arquitetura geral do projeto

```
Sistemas Monitorados (FS, .env, código-fonte)
        │
        │  Chokidar FS Watch (< 500ms)
        ▼
┌─────────────────────────────────────────────────────┐
│         🟢 AGENTE Node.js 18 (Gustavo Martins)      │
│                                                     │
│  Scanner Engine ──► Regex Engine ──► Data Masking   │
│                                          │          │
│                                    Cifra RSA-4096   │
│                                          │          │
│                                   Assina HMAC-SHA256 │
│                                          │          │
│                                   Buffer + Watchdog │
└─────────────────────────────────────────────────────┘
        │
        │  HTTPS + mTLS  │  POST /alerts  │  X-Agent-Token  │  RSA-4096
        ▼
┌─────────────────────────────────────────────────────┐
│       🔵 SERVIDOR Java 17 + Spring Boot (Isadora)   │
│                                                     │
│  Auth → HMAC Validation → RSA Decrypt → Chain of   │
│  Responsibility → Strategy → Factory → Audit Log   │
└─────────────────────────────────────────────────────┘
        │
        │  JPA + Prepared Statements
        ▼
┌──────────────────────────────┐
│  🗄️ PostgreSQL (Rede Isolada) │
└──────────────────────────────┘
        │
        │  REST API + JWT
        ▼
┌──────────────────────────────┐
│  🟣 React + Vite (João Paulo) │
└──────────────────────────────┘
```

---

## 4. Estrutura de arquivos do agente

```
sentinela-agent/
├── src/
│   ├── index.js              # Entry point — Chokidar + watchdog + pipeline
│   ├── scanner/
│   │   └── index.js          # Scanner Engine — leitura de arquivos
│   ├── rules/
│   │   └── index.js          # Regras de detecção (RULES[])
│   ├── masking/
│   │   └── index.js          # Data Masking — segredos nunca em claro
│   ├── crypto/
│   │   └── index.js          # RSA-4096 + HMAC-SHA256 + SHA-256 checksum
│   ├── transport/
│   │   └── index.js          # HTTP client — auth JWT + envio de alertas
│   ├── buffer/
│   │   └── index.js          # Buffer resiliente + backoff exponencial
│   └── config/
│       └── logger.js         # Logger seguro (nunca imprime segredos)
├── Dockerfile                # Container Alpine non-root
├── docker-compose.yml        # Stack completa com redes isoladas
├── package.json
├── .env.example              # Template de variáveis (NUNCA versionar .env)
└── .gitignore
```

---

## 5. Como funciona — fluxo completo

1. **Inicialização** (`src/index.js`): o agente carrega as variáveis de ambiente, valida que todas as obrigatórias estão presentes e inicia o watcher Chokidar nos caminhos configurados em `WATCH_PATHS`.

2. **Detecção de mudança**: Chokidar detecta criação ou alteração de arquivo em menos de 500ms (SLA definido na arquitetura).

3. **Scan** (`src/scanner/index.js`): o arquivo é lido (Stream API para arquivos > 50MB) e cada regra em `RULES` é aplicada via regex.

4. **Mascaramento** (`src/masking/index.js`): **antes de qualquer coisa**, o segredo real é substituído pela versão mascarada (ex: `AKIA*********LE`). O valor real **nunca sai do arquivo escaneado**.

5. **Construção do payload mascarado**: objeto JSON com `type`, `severity`, `agent_id`, `event_time`, `file_path`, `secret_preview` (mascarado), `rule_id`, `line`.

6. **Cifragem RSA-4096** (`src/crypto/index.js`): o payload JSON é cifrado com a chave pública do servidor. Apenas o servidor (com a chave privada, protegida por Jasypt) consegue decifrar.

7. **Assinatura HMAC-SHA256**: o payload original (antes de cifrar) é assinado com o `HMAC_SECRET` compartilhado. O servidor valida essa assinatura; se qualquer byte for alterado em trânsito, o alerta é descartado.

8. **Checksum SHA-256**: calculado para deduplicação no servidor. Se o mesmo alerta for enviado N vezes (retry após falha de rede), apenas 1 é persistido no banco.

9. **Envio** (`src/transport/index.js`): o envelope cifrado é enviado via `POST /alerts` com os headers `Authorization: Bearer <jwt>`, `X-Agent-Token` e `X-Request-ID`.

10. **Fallback com buffer** (`src/buffer/index.js`): se o servidor estiver offline (503/500/timeout), o envelope **já cifrado** é enfileirado localmente e reenviado com backoff exponencial: `1s → 2s → 4s → 8s → ... → máx. 5min`.

---

## 6. Pipeline de segurança (passo a passo)

Conforme definido na arquitetura, cada alerta percorre exatamente estes 12 passos:

```
 1. Regex detecta segredo
 2. Data Masking (AKIA*****)
 3. Cifra RSA-4096
 4. Assina HMAC-SHA256
 5. POST /alerts
 6. [Servidor] Valida X-Agent-Token
 7. [Servidor] Valida assinatura HMAC
 8. [Servidor] Decifra RSA (chave privada)
 9. [Servidor] Chain of Responsibility
10. [Servidor] Strategy (severidade)
11. [Servidor] Persiste mascarado
12. [Servidor] Audit Log imutável
```

Os passos 1–5 são implementados pelo agente (Gustavo). Os passos 6–12 são do servidor Java (Isadora).

---

## 7. Configuração e variáveis de ambiente

Copie `.env.example` para `.env` e preencha:

```bash
cp .env.example .env
```

| Variável | Obrigatório | Descrição |
|---|---|---|
| `AGENT_ID` | ✅ | ID do agente (obtido em `POST /agents/register`) |
| `AGENT_TOKEN` | ✅ | UUID único do agente — trate como senha, **nunca versionar** |
| `API_BASE_URL` | ✅ | URL base da API Java (ex: `https://api.sentinela.io/v1`) |
| `SERVER_PUBLIC_KEY` | ✅ | Chave pública RSA-4096 PEM do servidor (obtida no registro) |
| `HMAC_SECRET` | ✅ | Segredo compartilhado para HMAC-SHA256 (64 bytes hex) |
| `WATCH_PATHS` | ✅ | Caminhos a monitorar, separados por vírgula |
| `ENVIRONMENT` | — | `DEVELOPMENT` \| `STAGING` \| `PRODUCTION` (default: DEVELOPMENT) |
| `INITIAL_RETRY_DELAY_MS` | — | Delay inicial do backoff (default: `1000`) |
| `MAX_RETRY_DELAY_MS` | — | Delay máximo do backoff (default: `300000` = 5min) |
| `BUFFER_MAX_SIZE` | — | Máximo de alertas no buffer (default: `500`) |
| `LOG_LEVEL` | — | `debug` \| `info` \| `warn` \| `error` (default: `info`) |

### Como gerar o HMAC_SECRET

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Onde obter AGENT_ID, AGENT_TOKEN e SERVER_PUBLIC_KEY

Esses valores são retornados pelo endpoint `POST /agents/register` do servidor Java (Isadora). Na primeira execução, o servidor gera e retorna o token e a chave pública. **Salve imediatamente como variável de ambiente.**

---

## 8. Como rodar localmente

### Pré-requisitos

- Node.js 18 LTS ou superior
- npm 9+

### Instalação

```bash
cd sentinela-agent
npm install
cp .env.example .env
# edite o .env com os valores reais
```

### Execução

```bash
# Produção
npm start

# Desenvolvimento (reinicia ao salvar arquivos)
npm run dev
```

### Testes

```bash
npm test
```

---

## 9. Como rodar com Docker

### Apenas o agente

```bash
cd sentinela-agent
docker build -t sentinela-agent:latest .
docker run --env-file .env sentinela-agent:latest
```

### Stack completa (todos os serviços)

```bash
# Na raiz do projeto (onde está o docker-compose.yml)
docker compose up -d

# Ver logs do agente
docker compose logs -f sentinela-agent

# Parar tudo
docker compose down
```

### Variáveis necessárias no `.env` raiz (para o compose)

```dotenv
POSTGRES_DB=sentinela
POSTGRES_USER=sentinela
POSTGRES_PASSWORD=senha_forte_aqui
```

---

## 10. Módulos implementados

### `src/index.js` — Entry Point

- Valida variáveis de ambiente obrigatórias na inicialização (falha com mensagem clara se faltar alguma)
- Inicia o watcher Chokidar com `ignoreInitial: false` (escaneia arquivos existentes na inicialização)
- Implementa `awaitWriteFinish` para evitar leitura de arquivo sendo escrito
- Ignora binários, `node_modules`, `.git`
- Watchdog com `setInterval(30s)` que reinicia o watcher se travar
- Graceful shutdown nos sinais `SIGINT` e `SIGTERM`
- Registra latência de cada detecção e alerta se ultrapassar o SLA de 500ms

### `src/scanner/index.js` — Scanner Engine

- Usa `fs.readFileSync` para arquivos pequenos (mais rápido, atende SLA)
- Usa `readline` sobre `createReadStream` para arquivos > 50MB (evita OOM)
- Ignora arquivos inacessíveis/removidos sem crash
- Retorna apenas dados mascarados — nunca o segredo real

### `src/rules/index.js` — Regras de Detecção

- Regras para: AWS Access Key ID, AWS Secret Key, GitHub Token, API Keys genéricas, Private Keys (PEM), senhas em URLs, `.env` secrets, Slack tokens, secrets genéricos
- Cada regra tem `id`, `name`, `pattern`, `severity` e `maskFn`
- A `maskFn` é chamada pelo módulo de masking antes de qualquer uso do valor

### `src/masking/index.js` — Data Masking

- `applyMask(rawMatch, maskFn)`: aplica a máscara da regra com fallback seguro
- `sanitizeForLog(obj)`: remove recursivamente campos sensíveis de objetos antes de logar

### `src/crypto/index.js` — Criptografia

- `encryptRSA(payload, publicKeyPem)`: cifragem com `RSA_PKCS1_OAEP_PADDING` + `sha256`
- `signHMAC(payload, hmacSecret)`: HMAC-SHA256 em hex
- `checksumSHA256(payload)`: SHA-256 em hex para deduplicação
- `buildEncryptedEnvelope(maskedPayload, pubKey, hmacSecret)`: monta o envelope completo

### `src/transport/index.js` — Transporte HTTP

- Gerenciamento automático de JWT (login, refresh, expiração com margem de 60s)
- Trata todos os status HTTP conforme a spec da API: 200 (dup), 401 (re-auth), 409 (dup), 429 (Retry-After), 5xx (buffer)
- Nunca loga JWT, AGENT_TOKEN ou qualquer segredo

### `src/buffer/index.js` — Buffer Resiliente

- Fila FIFO em memória com limite configurável
- Backoff exponencial: `1s → 2s → 4s → 8s → 16s → ... → 5min`
- Reseta o delay após sucesso no reenvio
- Descarta alertas mais antigos quando o buffer está cheio (log de aviso)

### `src/config/logger.js` — Logger Seguro

- Redação automática de tokens Bearer, chaves AWS, tokens GitHub, chaves PEM
- Respeita `LOG_LEVEL` do ambiente
- Formato com timestamp ISO8601 para auditoria

---

## 11. Regras de detecção (Rules)

| Rule ID | Nome | Severidade |
|---|---|---|
| `AWS_ACCESS_KEY_001` | AWS Access Key ID (`AKIA...`) | CRITICAL |
| `AWS_SECRET_KEY_002` | AWS Secret Access Key (40 chars) | CRITICAL |
| `GITHUB_TOKEN_003` | GitHub PAT (`ghp_`, `gho_`, `ghs_`) | CRITICAL |
| `GENERIC_API_KEY_004` | API Key genérica | MEDIUM |
| `PRIVATE_KEY_005` | Chave Privada PEM | CRITICAL |
| `PASSWORD_IN_URL_006` | Senha em URL de conexão | CRITICAL |
| `DOTENV_SECRET_007` | Secret em arquivo `.env` | HIGH |
| `SLACK_TOKEN_008` | Slack Token (`xox...`) | CRITICAL |
| `GENERIC_SECRET_009` | Atribuição genérica de secret | LOW |

> Os padrões regex foram definidos por **Caio & André** e integrados ao agente por **Gustavo Martins**. Para adicionar novas regras, edite `src/rules/index.js`.

---

## 12. Criptografia RSA-4096 + HMAC-SHA256

### Por que RSA-4096?

O agente **nunca possui a chave privada**. Ele só conhece a chave pública do servidor. Assim, mesmo que o agente seja comprometido, os dados cifrados não podem ser decifrados sem a chave privada (que fica no servidor, protegida por Jasypt).

### Envelope enviado à API

```json
{
  "data":       "<payload JSON cifrado com RSA-4096, Base64>",
  "signature":  "<HMAC-SHA256 do payload original, hex>",
  "checksum":   "<SHA-256 do payload original, hex>",
  "agent_id":   "agent-prod-01",
  "severity":   "CRITICAL",
  "event_time": "2025-01-15T10:30:00.123Z",
  "rule_id":    "AWS_ACCESS_KEY_001",
  "file_path":  "/app/config/.env"
}
```

> `data`, `signature` e `checksum` são calculados sobre o payload **já mascarado**. O segredo real nunca entra no payload.

### Por que HMAC-SHA256?

Se qualquer byte do envelope for alterado em trânsito (ataque man-in-the-middle), o servidor recalcula o HMAC e percebe a divergência, descartando o alerta imediatamente.

### Por que SHA-256 checksum?

Para deduplicação. Se o agente enviar o mesmo alerta 3 vezes por conta de retries após falha de rede, o servidor persiste apenas 1 registro (retorna `200` ou `409` para as duplicatas).

---

## 13. Data Masking — regra de ouro

> **O segredo real NUNCA deve aparecer em: payload enviado à API, logs do console, buffer local.**

Exemplos de mascaramento por regra:

| Valor original | Após mascaramento |
|---|---|
| `AKIAIOSFODNN7EXAMPLE` | `AKIA*********LE` |
| `ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456` | `ghp_aBc****Z123` |
| `-----BEGIN RSA PRIVATE KEY-----` | `[PRIVATE KEY REDACTED]` |
| `SECRET=minha_senha_super_secreta` | `SECRET= [REDACTED]` |
| `jdbc:mysql://user:senha@host/db` | `jdbc:mysql://user:****@host/db` |

O `secret_preview` (versão mascarada) é o único dado salvo no banco de dados pelo servidor.

---

## 14. Resiliência e Backoff Exponencial

Conforme requisito da arquitetura (`RNF — Resiliência & Backoff`):

```
Servidor cai
    │
    ▼
Agente tenta enviar → FALHA (503/500/timeout)
    │
    ▼
Envelope (já cifrado) → AlertBuffer.enqueue()
    │
    ▼
Timer: aguarda 1s → tenta reenvio
    │
    ├── Sucesso → reseta delay para 1s
    │
    └── Falha → delay *= 2 → agenda próximo retry
               1s → 2s → 4s → 8s → 16s → 32s → ... → máx. 5min
```

O buffer aceita até `BUFFER_MAX_SIZE` (default: 500) envelopes. Quando cheio, o mais antigo é descartado com aviso no log.

---

## 15. Infraestrutura Docker (também Gustavo)

### Container do Agente (`Dockerfile`)

- **Imagem base:** `node:18-alpine` — mínima, sem shell desnecessário
- **Usuário:** `sentinela:1001` — non-root (requisito de segurança)
- **`dumb-init`:** garante propagação correta de SIGTERM/SIGINT para o processo Node
- **Build multi-stage:** dependências instaladas em stage separado, imagem final só tem o necessário
- **`read_only: true`** no compose (filesystem somente leitura, exceto `/tmp`)

### Redes Docker Isoladas

| Rede | Serviços | Acesso externo |
|---|---|---|
| `agent-net` | agente ↔ API Java | Sim (HTTPS para API) |
| `api-net` | API Java ↔ React | Sim (portas 8080 e 3000) |
| `db-net` | API Java ↔ PostgreSQL | **Não** (`internal: true`) |

> O PostgreSQL está em rede `internal: true` — **sem nenhuma rota para a internet**. Apenas o container da API Java consegue se conectar ao banco.

---

## 16. SLA e Requisitos de Desempenho

| Métrica | SLA | Onde é garantido |
|---|---|---|
| Latência evento → alerta | < 500ms | Scanner + pipeline criptográfica |
| Consumo de CPU do agente | < 5% | Stream API + Worker Threads para arquivos grandes |
| Taxa de falso positivo | < 2% | Qualidade das regras regex |
| Disponibilidade da API | 99.9% | Buffer + backoff (lado do agente) |
| JWT expira em | 15 min | Gerenciado automaticamente pelo `transport` |
| Rate limit | 100 req/min | Tratado com `429 + Retry-After` |
| Timestamp tolerance | ±30s | `event_time` sempre em UTC com `new Date().toISOString()` |

---

## 17. Requisitos Funcionais atendidos

| RF | Descrição | Implementado em |
|---|---|---|
| RF01 | Escanear arquivos e repositórios | `src/scanner/index.js` |
| RF02 | Identificar credenciais por regex | `src/rules/index.js` + `src/scanner/index.js` |
| RF03 | Enviar dados à API central | `src/transport/index.js` |
| RF04 | Classificar riscos (CRITICAL/MEDIUM/LOW) | `src/rules/index.js` (severidade por regra) |
| RF07 | Resiliência e mitigação de falhas de rede | `src/buffer/index.js` |

> RF05 (persistência), RF06 (alertas), RF08 (histórico) e RF09 (autenticação JWT no frontend) são responsabilidade do servidor Java (Isadora) e do frontend React (João Paulo).

---

## 18. Divisão de responsabilidades do time

| Membro | Camada | Tecnologia | Responsabilidades |
|---|---|---|---|
| **Gustavo Martins** | Agente + Docker | Node.js 18 | Scanner, crypto, masking, buffer, transporte, Dockerfile, docker-compose |
| **Isadora Lyra** | Servidor | Java 17 + Spring Boot 3 | API REST, Chain of Responsibility, Strategy, Factory, HMAC validation, RSA decrypt, Audit Log |
| **João Paulo** | Frontend | React + Vite | Dashboard, gráficos, autenticação JWT, CSP |
| **Caio & André** | Regras | (integradas no agente) | Padrões regex de detecção |

---

## 19. Regras e restrições importantes

### ❌ O que NUNCA fazer

- **Nunca versionar o `.env`** — ele contém `AGENT_TOKEN`, `HMAC_SECRET` e `SERVER_PUBLIC_KEY`
- **Nunca logar o valor real de um segredo** — o logger já redacta automaticamente, mas não contorne isso
- **Nunca hardcodar o `AGENT_TOKEN` ou `HMAC_SECRET` no código**
- **Nunca colocar o `AGENT_TOKEN` ou `HMAC_SECRET` em variáveis de ambiente do Docker Compose** — use `env_file` apontando para o `.env` local
- **Nunca salvar o payload não cifrado em disco**

### ✅ O que sempre fazer

- Sempre usar `process.env.AGENT_TOKEN` e `process.env.HMAC_SECRET`
- Sempre mascarar o segredo **antes** de criar o payload
- Sempre usar `event_time: new Date().toISOString()` (UTC) para respeitar a tolerância de ±30s do servidor
- Sempre enviar `X-Request-ID` único por requisição (uuid v4)
- Sempre respeitar o `Retry-After` retornado em respostas `429`
- Sempre validar as variáveis obrigatórias na inicialização (já feito em `src/index.js`)

---

## 20. Dependências

| Pacote | Versão | Uso |
|---|---|---|
| `chokidar` | ^3.6.0 | File system watcher — detecta alterações < 500ms |
| `axios` | ^1.7.2 | Cliente HTTP para comunicação com a API Java |
| `dotenv` | ^16.4.5 | Carregamento de variáveis de ambiente do `.env` |
| `uuid` | ^10.0.0 | Geração de `X-Request-ID` para cada requisição |
| `node-forge` | ^1.3.1 | Criptografia RSA (complementar ao módulo nativo `crypto`) |

> Todos os módulos de criptografia principais (`crypto`) são nativos do Node.js 18 — sem dependência de biblioteca externa para RSA e HMAC.

---

*Sentinela DevSecOps — Arquitetura v1.0 · Node.js 18 + Java 17 + Spring Boot 3 + React + Docker*
