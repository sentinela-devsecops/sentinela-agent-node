/**
 * Sentinela Agent — Scanner Engine
 *
 * Responsável: Gustavo Martins
 *
 * Responsabilidades:
 *  - Ler arquivos de forma segura (Stream API para arquivos grandes)
 *  - Aplicar as regras de detecção (RULES) via regex
 *  - Mascarar qualquer segredo ANTES de qualquer processamento posterior
 *  - Retornar lista de detecções com apenas dados mascarados
 *
 * SLA: Latência evento → alerta < 500ms (conforme RNF da arquitetura)
 */

import fs from 'fs';
import readline from 'readline';
import path from 'path';
import { RULES } from '../rules/index.js';
import { applyMask } from '../masking/index.js';
import logger from '../config/logger.js';

const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB — acima disso usa stream

/**
 * Escaneia um único arquivo em busca de segredos.
 * Para arquivos > 50MB usa readline (stream), senão lê tudo de uma vez.
 *
 * @param {string} filePath - Caminho absoluto do arquivo
 * @returns {Promise<Detection[]>} - Lista de detecções (com segredos mascarados)
 */
export async function scanFile(filePath) {
  const detections = [];

  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch {
    logger.warn(`[Scanner] Arquivo inacessível ou removido: ${filePath}`);
    return detections;
  }

  // Ignorar diretórios, symlinks e arquivos muito grandes (> 50MB ignorados por padrão)
  if (!stat.isFile()) return detections;

  if (stat.size > MAX_FILE_SIZE_BYTES) {
    logger.debug(`[Scanner] Arquivo grande (${(stat.size / 1024 / 1024).toFixed(1)}MB), usando stream: ${filePath}`);
    return await scanFileStream(filePath);
  }

  // Arquivo pequeno: leitura síncrona é mais rápida e atende SLA < 500ms
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    logger.warn(`[Scanner] Não foi possível ler ${filePath}: ${err.message}`);
    return detections;
  }

  for (const rule of RULES) {
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      const rawMatch = match[1] ?? match[0];
      const masked   = applyMask(rawMatch, rule.maskFn);

      detections.push({
        rule_id:        rule.id,
        rule_name:      rule.name,
        severity:       rule.severity,
        file_path:      filePath,
        line:           getLineNumber(content, match.index),
        secret_preview: masked,   // NUNCA o valor real
      });
    }
  }

  if (detections.length > 0) {
    logger.info(`[Scanner] ${detections.length} detecção(ões) em ${path.basename(filePath)}`);
  }

  return detections;
}

/**
 * Variante streaming para arquivos grandes (> 50MB).
 * Processa linha por linha sem carregar tudo na memória.
 */
async function scanFileStream(filePath) {
  return new Promise((resolve) => {
    const detections = [];
    const rl = readline.createInterface({
      input:     fs.createReadStream(filePath, { encoding: 'utf8' }),
      crlfDelay: Infinity,
    });

    let lineNumber = 0;

    rl.on('line', (line) => {
      lineNumber++;

      for (const rule of RULES) {
        const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
        let match;
        while ((match = regex.exec(line)) !== null) {
          const rawMatch = match[1] ?? match[0];
          const masked   = applyMask(rawMatch, rule.maskFn);

          detections.push({
            rule_id:        rule.id,
            rule_name:      rule.name,
            severity:       rule.severity,
            file_path:      filePath,
            line:           lineNumber,
            secret_preview: masked,
          });
        }
      }
    });

    rl.on('close', () => resolve(detections));
    rl.on('error', (err) => {
      logger.warn(`[Scanner] Erro no stream de ${filePath}: ${err.message}`);
      resolve(detections);
    });
  });
}

/**
 * Calcula o número da linha (1-based) de um match dentro do conteúdo.
 * @param {string} content
 * @param {number} matchIndex
 * @returns {number}
 */
function getLineNumber(content, matchIndex) {
  const lines = content.slice(0, matchIndex).split('\n');
  return lines.length;
}
