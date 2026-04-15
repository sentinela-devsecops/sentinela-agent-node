/**
 * Sentinela Agent — Entry Point
 *
 * Responsável: Gustavo Martins
 * Linguagem: Node.js 18 LTS (ESM)
 *
 * Inicializa:
 *  1. Carregamento de variáveis de ambiente (.env)
 *  2. Validação de configurações obrigatórias
 *  3. Watcher Chokidar nos caminhos configurados
 *  4. Pipeline: alteração detectada → scan → mask → cifra → assina → envia
 *  5. Watchdog para auto-restart em caso de crash do watcher
 *
 * Fluxo completo por arquivo alterado:
 *  Chokidar event → scanFile() → [detecções mascaradas]
 *    → buildEncryptedEnvelope(RSA-4096 + HMAC-SHA256)
 *    → sendAlert() [ou buffer se servidor offline]
 */

import 'dotenv/config';
import chokidar from 'chokidar';
import { scanFile }              from './scanner/index.js';
import { buildEncryptedEnvelope } from './crypto/index.js';
import { sendAlert }             from './transport/index.js';
import logger                    from './config/logger.js';

// ─────────────────────────────────────────────
//  Validação de configuração
// ─────────────────────────────────────────────

const REQUIRED_ENV = ['AGENT_ID', 'AGENT_TOKEN', 'API_BASE_URL', 'SERVER_PUBLIC_KEY', 'HMAC_SECRET'];
const missing = REQUIRED_ENV.filter(k => !process.env[k]);

if (missing.length > 0) {
  console.error(`[Sentinela] ERRO FATAL: Variáveis de ambiente obrigatórias ausentes: ${missing.join(', ')}`);
  console.error('[Sentinela] Copie .env.example para .env e preencha os valores.');
  process.exit(1);
}

const WATCH_PATHS    = (process.env.WATCH_PATHS ?? '.').split(',').map(p => p.trim()).filter(Boolean);
const SERVER_PUB_KEY = process.env.SERVER_PUBLIC_KEY;
const HMAC_SECRET    = process.env.HMAC_SECRET;
const AGENT_ID       = process.env.AGENT_ID;

// ─────────────────────────────────────────────
//  Pipeline principal
// ─────────────────────────────────────────────

/**
 * Processamento de um único arquivo alterado.
 * Toda a pipeline é assíncrona para não bloquear o event loop.
 *
 * @param {string} filePath
 */
async function processFile(filePath) {
  const t0 = Date.now();

  let detections;
  try {
    detections = await scanFile(filePath);
  } catch (err) {
    logger.error(`[Agent] Erro ao escanear ${filePath}: ${err.message}`);
    return;
  }

  if (detections.length === 0) return;

  for (const detection of detections) {
    const maskedPayload = {
      type:           'SECRET_EXPOSED',
      severity:       detection.severity,
      agent_id:       AGENT_ID,
      event_time:     new Date().toISOString(),
      file_path:      detection.file_path,
      secret_preview: detection.secret_preview, // já mascarado pelo scanner
      rule_id:        detection.rule_id,
      line:           detection.line,
    };

    let envelope;
    try {
      envelope = buildEncryptedEnvelope(maskedPayload, SERVER_PUB_KEY, HMAC_SECRET);
    } catch (err) {
      logger.error(`[Agent] Erro na cifragem: ${err.message}`);
      continue;
    }

    // Latência: log para monitorar SLA < 500ms
    const latencyMs = Date.now() - t0;
    logger.info(`[Agent] Detecção processada em ${latencyMs}ms | rule=${detection.rule_id} | severity=${detection.severity}`);

    if (latencyMs > 500) {
      logger.warn(`[Agent] SLA excedido: ${latencyMs}ms > 500ms para ${filePath}`);
    }

    // Envio (ou buffer se servidor offline)
    await sendAlert(envelope);
  }
}

// ─────────────────────────────────────────────
//  Watcher Chokidar
// ─────────────────────────────────────────────

function startWatcher() {
  logger.info(`[Agent] Iniciando monitoramento em: ${WATCH_PATHS.join(', ')}`);

  const watcher = chokidar.watch(WATCH_PATHS, {
    persistent:       true,
    ignoreInitial:    false,   // escaneia arquivos existentes na inicialização
    followSymlinks:   false,
    awaitWriteFinish: {
      stabilityThreshold: 300,  // aguarda 300ms após última escrita antes de processar
      pollInterval:       100,
    },
    ignored: [
      /node_modules/,
      /\.git/,
      /\.sentinela-buffer/,     // ignora o próprio buffer local
      /\.(jpg|jpeg|png|gif|mp4|mp3|zip|tar|gz|bin)$/i, // binários
    ],
  });

  watcher
    .on('add',    filePath => processFile(filePath))
    .on('change', filePath => processFile(filePath))
    .on('error',  err      => logger.error(`[Watcher] Erro: ${err.message}`))
    .on('ready',  ()       => logger.info('[Watcher] Varredura inicial concluída. Monitorando...'));

  return watcher;
}

// ─────────────────────────────────────────────
//  Watchdog — reinicia o watcher se travar
// ─────────────────────────────────────────────

let watcher = startWatcher();
let watchdogRestarts = 0;

setInterval(() => {
  if (!watcher || watcher.closed) {
    watchdogRestarts++;
    logger.warn(`[Watchdog] Watcher parado — reiniciando (restart #${watchdogRestarts})`);
    watcher = startWatcher();
  }
}, 30_000); // verifica a cada 30s

// ─────────────────────────────────────────────
//  Graceful Shutdown
// ─────────────────────────────────────────────

async function shutdown(signal) {
  logger.info(`[Agent] Recebido ${signal} — encerrando graciosamente...`);
  await watcher?.close();
  logger.info('[Agent] Watcher encerrado. Saindo.');
  process.exit(0);
}

process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('uncaughtException', (err) => {
  logger.error(`[Agent] Exceção não tratada: ${err.message}`);
});

process.on('unhandledRejection', (reason) => {
  logger.error(`[Agent] Promise rejeitada não tratada: ${reason}`);
});

logger.info(`[Sentinela Agent] v1.0.0 iniciado | Node ${process.version} | AGENT_ID=${AGENT_ID}`);
