/**
 * Sentinela Agent — Buffer de Resiliência
 *
 * Responsável: Gustavo Martins
 *
 * Quando o servidor estiver indisponível (503/500/timeout), os envelopes
 * já cifrados são armazenados em memória (buffer circular) e reenviados
 * com Exponential Backoff quando a conexão for restabelecida.
 *
 * Política:
 *  - Buffer máximo: configurável via BUFFER_MAX_SIZE (default 500)
 *  - Ao atingir o limite: os alertas mais antigos são descartados (FIFO)
 *  - Backoff: 1s → 2s → 4s → 8s → 16s → ... → máx. 5min (300s)
 *
 * Os envelopes já estão cifrados (RSA-4096) quando entram no buffer,
 * portanto não há risco de exposição mesmo que o processo seja inspecionado.
 */

import logger from '../config/logger.js';

const DEFAULT_MAX = 500;
const INITIAL_DELAY_MS = parseInt(process.env.INITIAL_RETRY_DELAY_MS ?? '1000', 10);
const MAX_DELAY_MS     = parseInt(process.env.MAX_RETRY_DELAY_MS ?? '300000', 10);

export class AlertBuffer {
  #queue       = [];
  #maxSize     = DEFAULT_MAX;
  #retryTimer  = null;
  #currentDelay = INITIAL_DELAY_MS;
  #sendFn      = null; // injetado em init()

  /**
   * @param {Function} sendFn - Função assíncrona que envia um envelope à API.
   *                            Deve lançar exceção em caso de falha.
   * @param {number}   maxSize
   */
  init(sendFn, maxSize = DEFAULT_MAX) {
    this.#sendFn  = sendFn;
    this.#maxSize = maxSize;
  }

  /**
   * Enfileira um envelope cifrado para reenvio posterior.
   * @param {object} envelope - Envelope retornado por buildEncryptedEnvelope()
   */
  enqueue(envelope) {
    if (this.#queue.length >= this.#maxSize) {
      const dropped = this.#queue.shift(); // descarta o mais antigo
      logger.warn(`[Buffer] Limite atingido. Descartando alerta mais antigo: rule=${dropped.rule_id}`);
    }

    this.#queue.push({ envelope, enqueuedAt: Date.now() });
    logger.info(`[Buffer] Alerta enfileirado. Fila: ${this.#queue.length}/${this.#maxSize}`);

    this.#scheduleRetry();
  }

  /** Número de alertas pendentes no buffer. */
  get pendingCount() {
    return this.#queue.length;
  }

  /** Inicia (ou reinicia) o timer de retry com backoff exponencial. */
  #scheduleRetry() {
    if (this.#retryTimer) return; // já há um retry agendado

    logger.info(`[Buffer] Próxima tentativa em ${this.#currentDelay / 1000}s`);

    this.#retryTimer = setTimeout(async () => {
      this.#retryTimer = null;
      await this.#flushBuffer();
    }, this.#currentDelay);
  }

  /** Tenta enviar todos os alertas do buffer em ordem (FIFO). */
  async #flushBuffer() {
    if (this.#queue.length === 0) {
      this.#resetBackoff();
      return;
    }

    logger.info(`[Buffer] Tentando reenviar ${this.#queue.length} alerta(s)...`);

    // Trabalha numa cópia para não corromper a fila durante a iteração
    const snapshot = [...this.#queue];
    const failed   = [];

    for (const item of snapshot) {
      try {
        await this.#sendFn(item.envelope);
        logger.info(`[Buffer] Alerta reenviado com sucesso: rule=${item.envelope.rule_id}`);
      } catch (err) {
        logger.warn(`[Buffer] Reenvio falhou: ${err.message}`);
        failed.push(item);
        break; // servidor ainda indisponível — para e reagenda
      }
    }

    // Atualiza a fila com o que ainda falhou
    this.#queue = failed.concat(this.#queue.slice(snapshot.length - failed.length));

    if (this.#queue.length > 0) {
      // Ainda há falhas: dobra o delay (backoff exponencial)
      this.#currentDelay = Math.min(this.#currentDelay * 2, MAX_DELAY_MS);
      this.#scheduleRetry();
    } else {
      this.#resetBackoff();
      logger.info('[Buffer] Fila esvaziada com sucesso.');
    }
  }

  /** Reseta o delay de backoff ao estado inicial após sucesso. */
  #resetBackoff() {
    this.#currentDelay = INITIAL_DELAY_MS;
  }
}

// Singleton exportado para uso em todo o agente
export const alertBuffer = new AlertBuffer();
