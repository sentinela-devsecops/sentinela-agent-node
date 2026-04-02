/**
 * Sentinela Agent — Módulo de Transporte (HTTP)
 *
 * Responsável: Gustavo Martins
 *
 * Responsabilidades:
 *  - Obter/renovar JWT via POST /auth/token e POST /auth/refresh
 *  - Enviar envelopes cifrados via POST /alerts
 *  - Em caso de 503/500: delegar ao AlertBuffer para retry com backoff
 *  - Em caso de 429: respeitar o header Retry-After
 *  - Nunca logar o JWT, AGENT_TOKEN ou qualquer segredo
 */

import axios from 'axios';
import { alertBuffer } from '../buffer/index.js';
import logger from '../config/logger.js';

const API_BASE    = process.env.API_BASE_URL  ?? 'https://api.sentinela.io/v1';
const AGENT_ID    = process.env.AGENT_ID      ?? '';
const AGENT_TOKEN = process.env.AGENT_TOKEN   ?? '';

if (!AGENT_ID || !AGENT_TOKEN) {
  throw new Error('[Transport] AGENT_ID e AGENT_TOKEN são obrigatórios. Configure o .env');
}

// Estado interno de autenticação — NUNCA expor externamente
let _accessToken  = null;
let _refreshToken = null;
let _tokenExpiry  = 0; // timestamp Unix (ms)

const http = axios.create({
  baseURL: API_BASE,
  timeout: 10_000,
  headers: {
    'Content-Type':  'application/json',
    'X-Agent-Token': AGENT_TOKEN,
  },
});

// ─────────────────────────────────────────────
//  Autenticação
// ─────────────────────────────────────────────

/**
 * Garante que existe um JWT válido. Se expirado (ou faltando),
 * tenta refresh; se não houver refresh token, faz login completo.
 */
async function ensureAuthenticated() {
  const now = Date.now();

  // Token ainda válido (com margem de 60s para evitar expiry durante a chamada)
  if (_accessToken && now < _tokenExpiry - 60_000) return;

  if (_refreshToken) {
    try {
      await refreshJWT();
      return;
    } catch {
      logger.warn('[Transport] Refresh falhou — fazendo login completo');
    }
  }

  await loginAgent();
}

/** POST /auth/token — obtém JWT inicial */
async function loginAgent() {
  const body = {
    agent_token: AGENT_TOKEN,
    agent_id:    AGENT_ID,
    timestamp:   new Date().toISOString(),
  };

  const { data } = await http.post('/auth/token', body);

  _accessToken  = data.access_token;
  _refreshToken = data.refresh_token;
  _tokenExpiry  = Date.now() + (data.expires_in ?? 900) * 1000;

  logger.info('[Transport] Autenticado com sucesso (JWT obtido)');
}

/** POST /auth/refresh — renova JWT sem credenciais completas */
async function refreshJWT() {
  const { data } = await http.post(
    '/auth/refresh',
    { refresh_token: _refreshToken },
    { headers: { 'X-Agent-Token': AGENT_TOKEN } }
  );

  _accessToken  = data.access_token;
  _refreshToken = data.refresh_token ?? _refreshToken;
  _tokenExpiry  = Date.now() + (data.expires_in ?? 900) * 1000;

  logger.info('[Transport] JWT renovado com sucesso');
}

// ─────────────────────────────────────────────
//  Envio de Alertas
// ─────────────────────────────────────────────

/**
 * Envia um envelope cifrado para POST /alerts.
 * Em caso de falha de servidor (5xx) ou rede, delega ao buffer.
 * Em caso de 429, respeita o Retry-After antes de retentar.
 *
 * @param {object} envelope - Retornado por buildEncryptedEnvelope()
 */
export async function sendAlert(envelope) {
  try {
    await ensureAuthenticated();
  } catch (err) {
    logger.error(`[Transport] Falha de autenticação — armazenando no buffer: ${err.message}`);
    alertBuffer.enqueue(envelope);
    return;
  }

  try {
    const res = await http.post('/alerts', envelope, {
      headers: {
        Authorization:  `Bearer ${_accessToken}`,
        'X-Request-ID': generateRequestId(),
      },
    });

    if (res.status === 200) {
      // 200 = alerta duplicado ignorado (idempotência por checksum SHA-256)
      logger.debug('[Transport] Alerta duplicado ignorado pelo servidor (checksum já existe)');
    } else {
      logger.info(`[Transport] Alerta enviado. ID: ${res.data?.alert_id ?? 'n/a'}`);
    }
  } catch (err) {
    const status = err.response?.status;

    if (status === 401) {
      // Token inválido ou expirado: força novo login e re-enfileira
      logger.warn('[Transport] 401 — Forçando re-autenticação');
      _accessToken = null;
      alertBuffer.enqueue(envelope);
      return;
    }

    if (status === 409) {
      // Duplicado: descarta silenciosamente (checksum SHA-256 já existe)
      logger.debug('[Transport] 409 — Alerta duplicado descartado');
      return;
    }

    if (status === 429) {
      const retryAfter = parseInt(err.response.headers['retry-after'] ?? '60', 10);
      logger.warn(`[Transport] 429 Rate limit — aguardando ${retryAfter}s`);
      await sleep(retryAfter * 1000);
      alertBuffer.enqueue(envelope);
      return;
    }

    // 500 / 503 / timeout / rede: buffer + backoff
    logger.warn(`[Transport] Falha no envio (${status ?? 'rede'}) — enfileirando para retry`);
    alertBuffer.enqueue(envelope);
  }
}

// ─────────────────────────────────────────────
//  Registro de Agente
// ─────────────────────────────────────────────

/**
 * POST /agents/register — chamado na primeira execução do agente.
 * Retorna agent_token, public_key e agent_id.
 * O agent_token deve ser salvo como variável de ambiente.
 *
 * @param {object} registrationData
 * @returns {object} - { agent_id, agent_token, public_key, rate_limit, created_at }
 */
export async function registerAgent(registrationData) {
  const { data } = await http.post('/agents/register', registrationData);
  logger.info(`[Transport] Agente registrado: ${data.agent_id}`);
  return data;
}

/**
 * GET /agents/{id}/status — health e métricas do agente
 */
export async function getAgentStatus() {
  await ensureAuthenticated();
  const { data } = await http.get(`/agents/${AGENT_ID}/status`, {
    headers: { Authorization: `Bearer ${_accessToken}` },
  });
  return data;
}

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────

function generateRequestId() {
  return crypto.randomUUID ? crypto.randomUUID() : `req-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Inicializa o buffer com a função de envio real
alertBuffer.init(sendAlert);
