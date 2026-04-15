/**
 * Sentinela Agent — Módulo de Criptografia
 *
 * Responsável: Gustavo Martins
 *
 * Implementa:
 *  1. Cifragem RSA-4096 com a chave pública do servidor
 *  2. Assinatura HMAC-SHA256 do payload original
 *  3. Checksum SHA-256 para deduplicação no servidor
 *
 * REGRA DE SEGURANÇA:
 *  - A chave pública do servidor vem de variável de ambiente (SERVER_PUBLIC_KEY)
 *  - O segredo HMAC vem de variável de ambiente (HMAC_SECRET)
 *  - Nenhuma chave pode ser hardcoded no código
 */

import crypto from 'crypto';

/**
 * Cifra um payload (string JSON) com RSA-4096 usando a chave pública do servidor.
 * Retorna o texto cifrado em Base64.
 *
 * @param {string} rawPayload - JSON stringificado do payload original (já mascarado)
 * @param {string} publicKeyPem - Chave pública PEM do servidor
 * @returns {string} - Base64 do payload cifrado
 */
export function encryptRSA(rawPayload, publicKeyPem) {
  if (!publicKeyPem || !publicKeyPem.includes('BEGIN PUBLIC KEY')) {
    throw new Error('[Crypto] SERVER_PUBLIC_KEY inválida ou ausente');
  }

  const encrypted = crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(rawPayload, 'utf8')
  );

  return encrypted.toString('base64');
}

/**
 * Gera a assinatura HMAC-SHA256 do payload original.
 * O servidor valida essa assinatura para garantir integridade.
 *
 * @param {string} rawPayload - JSON stringificado do payload original
 * @param {string} hmacSecret - Segredo compartilhado (de env var HMAC_SECRET)
 * @returns {string} - Hex da assinatura HMAC-SHA256
 */
export function signHMAC(rawPayload, hmacSecret) {
  if (!hmacSecret) {
    throw new Error('[Crypto] HMAC_SECRET não configurado');
  }

  return crypto
    .createHmac('sha256', hmacSecret)
    .update(rawPayload)
    .digest('hex');
}

/**
 * Calcula o checksum SHA-256 do payload para deduplicação no servidor.
 * Se o mesmo alerta for enviado N vezes (falha de rede + retry), apenas 1 é persistido.
 *
 * @param {string} rawPayload - JSON stringificado do payload original
 * @returns {string} - Hex do SHA-256
 */
export function checksumSHA256(rawPayload) {
  return crypto.createHash('sha256').update(rawPayload).digest('hex');
}

/**
 * Constrói o envelope completo pronto para envio à API:
 *  - data      : payload cifrado em Base64 (RSA-4096)
 *  - signature : HMAC-SHA256 do payload original (hex)
 *  - checksum  : SHA-256 do payload original (hex) — para deduplicação
 *  - agent_id, severity, event_time ficam em claro para roteamento pelo servidor
 *
 * @param {object} maskedPayload - Payload já com segredos mascarados
 * @param {string} publicKeyPem
 * @param {string} hmacSecret
 * @returns {object} - Envelope pronto para POST /alerts
 */
export function buildEncryptedEnvelope(maskedPayload, publicKeyPem, hmacSecret) {
  const raw = JSON.stringify(maskedPayload);

  const data      = encryptRSA(raw, publicKeyPem);
  const signature = signHMAC(raw, hmacSecret);
  const checksum  = checksumSHA256(raw);

  return {
    data,
    signature,
    checksum,
    agent_id:   maskedPayload.agent_id,
    severity:   maskedPayload.severity,
    event_time: maskedPayload.event_time,
    rule_id:    maskedPayload.rule_id,
    file_path:  maskedPayload.file_path,
  };
}
