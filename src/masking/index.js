/**
 * Sentinela Agent — Módulo de Data Masking
 *
 * Responsável: Gustavo Martins
 *
 * REGRA DE OURO: O segredo real NUNCA deve aparecer em:
 *  - Payloads enviados à API
 *  - Logs do console
 *  - Buffer local
 *
 * Apenas o `secret_preview` mascarado (ex: AKIA*********LE) é armazenado/enviado.
 */

/**
 * Aplica a função de máscara de uma regra ao trecho detectado.
 * @param {string} rawMatch  - Trecho original detectado pelo regex
 * @param {Function} maskFn  - Função de máscara da regra
 * @returns {string}         - Versão mascarada
 */
export function applyMask(rawMatch, maskFn) {
  try {
    return maskFn(rawMatch);
  } catch {
    // Fallback seguro: nunca expõe o valor real
    return '[REDACTED]';
  }
}

/**
 * Sanitiza um objeto inteiro removendo qualquer campo que possa conter
 * segredos reais antes de serializar para log ou rede.
 *
 * @param {object} obj - Objeto a sanitizar
 * @returns {object}   - Cópia sanitizada
 */
export function sanitizeForLog(obj) {
  const SENSITIVE_KEYS = /secret|password|passwd|token|key|auth|credential|private/i;

  function recurse(val, depth = 0) {
    if (depth > 10) return '[DEEP_OBJECT]';
    if (val === null || val === undefined) return val;
    if (typeof val === 'string') return val; // strings já devem ter sido mascaradas antes
    if (Array.isArray(val)) return val.map(v => recurse(v, depth + 1));
    if (typeof val === 'object') {
      const safe = {};
      for (const [k, v] of Object.entries(val)) {
        if (SENSITIVE_KEYS.test(k)) {
          safe[k] = '[REDACTED]';
        } else {
          safe[k] = recurse(v, depth + 1);
        }
      }
      return safe;
    }
    return val;
  }

  return recurse(obj);
}
