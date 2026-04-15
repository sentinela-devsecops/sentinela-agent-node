# ============================================================
# Sentinela Agent — Dockerfile
# Responsável (Infraestrutura Docker): Gustavo Martins
#
# Regras da arquitetura:
#  - Imagem Alpine (mínima, sem shell desnecessário em produção)
#  - Executa como usuário non-root (sentinela:1001)
#  - Rede: agent-net (isolada)
#  - Nenhuma variável secreta no Dockerfile — tudo via env_file no compose
# ============================================================

FROM node:18-alpine AS base

# Instala dependências de SO mínimas
RUN apk add --no-cache dumb-init

# Usuário non-root para segurança
RUN addgroup -g 1001 sentinela && \
    adduser  -u 1001 -G sentinela -s /bin/sh -D sentinela

WORKDIR /app

# ── Instala dependências de produção ──────────────────────
FROM base AS deps
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# ── Imagem final ──────────────────────────────────────────
FROM base AS final

# Copia dependências instaladas
COPY --from=deps --chown=sentinela:sentinela /app/node_modules ./node_modules

# Copia código-fonte
COPY --chown=sentinela:sentinela src/ ./src/
COPY --chown=sentinela:sentinela package.json ./

# Executa como non-root
USER sentinela

# dumb-init garante propagação correta de sinais (SIGTERM/SIGINT)
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/index.js"]

# Healthcheck básico — o watchdog interno também monitora
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "console.log('ok')" || exit 1
