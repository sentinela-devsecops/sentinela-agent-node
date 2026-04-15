/**
 * Sentinela Agent — Logger Seguro
 *
 * Responsável: Gustavo Martins
 *
 * Logger minimalista que:
 *  1. NUNCA imprime segredos, tokens ou chaves privadas
 *  2. Respeita o nível configurado em LOG_LEVEL
 *  3. Formata logs com timestamp ISO8601 para facilitar auditoria
 */

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const currentLevel = LEVELS[process.env.LOG_LEVEL?.toLowerCase()] ?? LEVELS.info;

// Padrões que NÃO devem jamais aparecer em logs
const SECRET_PATTERNS = [
  /Bearer\s+[A-Za-z0-9\-_.~+/]+=*/g,
  /AKIA[0-9A-Z]{16}/g,
  /ghp_[A-Za-z0-9]{36}/g,
  /"agent_token"\s*:\s*"[^"]+"/g,
  /"access_token"\s*:\s*"[^"]+"/g,
  /"refresh_token"\s*:\s*"[^"]+"/g,
  /-----BEGIN[\s\S]*?-----END[^-]+-----/g,
];

function redactSecrets(msg) {
  let safe = String(msg);
  for (const pattern of SECRET_PATTERNS) {
    safe = safe.replace(pattern, '[REDACTED]');
  }
  return safe;
}

function log(level, msg) {
  if (LEVELS[level] < currentLevel) return;
  const ts   = new Date().toISOString();
  const safe = redactSecrets(msg);
  const line = `[${ts}] [${level.toUpperCase().padEnd(5)}] ${safe}`;

  if (level === 'error' || level === 'warn') {
    console.error(line);
  } else {
    console.log(line);
  }
}

const logger = {
  debug: (msg) => log('debug', msg),
  info:  (msg) => log('info',  msg),
  warn:  (msg) => log('warn',  msg),
  error: (msg) => log('error', msg),
};

export default logger;
