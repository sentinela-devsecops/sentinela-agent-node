/**
 * Sentinela Agent — Regras de Detecção de Segredos
 *
 * Responsável pelas regras: Caio & André (conforme arquitetura)
 * Integração/uso no scanner: Gustavo Martins
 *
 * Cada regra contém:
 *  - id        : identificador único (usado em rule_id nos alertas)
 *  - name      : nome legível
 *  - pattern   : RegExp para detecção
 *  - severity  : CRITICAL | MEDIUM | LOW
 *  - maskFn    : função para mascarar o segredo real antes de qualquer log/envio
 */

export const RULES = [
  {
    id: 'AWS_ACCESS_KEY_001',
    name: 'AWS Access Key ID',
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    severity: 'CRITICAL',
    maskFn: (match) => `${match.slice(0, 4)}*********${match.slice(-2)}`,
  },
  {
    id: 'AWS_SECRET_KEY_002',
    name: 'AWS Secret Access Key',
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    severity: 'CRITICAL',
    maskFn: (match) => `${match.slice(0, 4)}****************************${match.slice(-4)}`,
  },
  {
    id: 'GITHUB_TOKEN_003',
    name: 'GitHub Personal Access Token',
    pattern: /\b(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/g,
    severity: 'CRITICAL',
    maskFn: (match) => `${match.slice(0, 6)}****${match.slice(-4)}`,
  },
  {
    id: 'GENERIC_API_KEY_004',
    name: 'Generic API Key',
    pattern: /(?:api[_\-]?key|apikey|api[_\-]?secret)\s*[:=]\s*['"]?([A-Za-z0-9\-_]{20,})/gi,
    severity: 'MEDIUM',
    maskFn: (match) => match.replace(/(['"]?)([A-Za-z0-9\-_]{4})([A-Za-z0-9\-_]{12,})([A-Za-z0-9\-_]{4})(['"]?)/, '$1$2****$4$5'),
  },
  {
    id: 'PRIVATE_KEY_005',
    name: 'Private Key (PEM)',
    pattern: /-----BEGIN\s(?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'CRITICAL',
    maskFn: () => '[PRIVATE KEY REDACTED]',
  },
  {
    id: 'PASSWORD_IN_URL_006',
    name: 'Password in URL',
    pattern: /(?:https?|ftp|jdbc):\/\/[^:@\s]+:([^@\s]{6,})@/gi,
    severity: 'CRITICAL',
    maskFn: (match) => match.replace(/:([^@\s]{6,})@/, ':****@'),
  },
  {
    id: 'DOTENV_SECRET_007',
    name: 'Secret in .env file',
    pattern: /^(?:SECRET|PASSWORD|PASSWD|PASS|PWD|TOKEN|KEY|AUTH)\s*=\s*['"]?(.+)/gim,
    severity: 'HIGH',
    maskFn: (match) => match.replace(/=\s*['"]?(.+)/, '= [REDACTED]'),
  },
  {
    id: 'SLACK_TOKEN_008',
    name: 'Slack Token',
    pattern: /\b(xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{20,30})\b/g,
    severity: 'CRITICAL',
    maskFn: (match) => `${match.slice(0, 10)}****${match.slice(-4)}`,
  },
  {
    id: 'GENERIC_SECRET_009',
    name: 'Generic Secret Assignment',
    pattern: /(?:secret|credential|credentials)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
    severity: 'LOW',
    maskFn: (match) => match.replace(/['"]([^'"]{8,})['"]/, '"[REDACTED]"'),
  },
];
