/**
 * Nansen CLI - x402 Auto-Payment Handler
 * Detects 402 responses and auto-signs payment using local wallet.
 * Supports EVM (EIP-3009 on Base) and Solana (SPL TransferChecked).
 */

import { createEvmPaymentPayload, isEvmNetwork } from './x402-evm.js';
import {
  createSvmPaymentPayload,
  isSvmNetwork,
  fetchRecentBlockhash,
  getSolanaRpcUrl,
} from './x402-svm.js';

/**
 * Parse PaymentRequirements from a 402 response.
 * @param {Response} response - The 402 HTTP response
 * @returns {object|null} Parsed requirements or null
 */
export function parsePaymentRequirements(response) {
  const header = response.headers.get('payment-required');
  if (!header) return null;

  try {
    const decoded = JSON.parse(atob(header));
    // V2 format: { accepts: [...], ... }
    if (decoded.accepts && Array.isArray(decoded.accepts)) {
      return decoded.accepts;
    }
    // Can be a single object or array of requirements
    return Array.isArray(decoded) ? decoded : [decoded];
  } catch {
    return null;
  }
}

/**
 * Rank payment requirements. Prefers EVM (gasless) over Solana.
 * Returns all supported requirements in priority order.
 */
function rankRequirements(requirements) {
  const ranked = [];
  // EVM first (gasless for client)
  for (const r of requirements) {
    if (isEvmNetwork(r.network)) ranked.push(r);
  }
  // Then Solana
  for (const r of requirements) {
    if (isSvmNetwork(r.network)) ranked.push(r);
  }
  return ranked;
}

/**
 * Build a payment signature for a single requirement.
 * @returns {string|null} Base64 payment signature, or null on failure
 */
async function buildPaymentForRequirement(requirement, exported, url) {
  if (isEvmNetwork(requirement.network)) {
    return createEvmPaymentPayload(
      requirement,
      exported.evm.privateKey,
      exported.evm.address,
      url,
    );
  }

  if (isSvmNetwork(requirement.network)) {
    const rpcUrl = getSolanaRpcUrl(requirement.network);
    const blockhash = await fetchRecentBlockhash(rpcUrl);
    return createSvmPaymentPayload(
      requirement,
      exported.solana.privateKey,
      exported.solana.address,
      url,
      blockhash,
    );
  }

  return null;
}

/**
 * Generate payment signatures for all viable payment options, in priority order.
 * Yields { signature, network } objects. Caller should try each until one succeeds.
 *
 * @param {Response} response - The 402 HTTP response
 * @param {string} url - The original request URL
 * @param {object} options - { password, walletName }
 * @returns {AsyncGenerator<{ signature: string, network: string }>}
 */
export async function* createPaymentSignatures(response, url, options = {}) {
  const requirements = parsePaymentRequirements(response);
  if (!requirements || requirements.length === 0) return;

  const ranked = rankRequirements(requirements);
  if (ranked.length === 0) return;

  const password = options.password || process.env.NANSEN_WALLET_PASSWORD;
  if (!password) return;

  let exportWallet, listWallets;
  try {
    const walletMod = await import('./wallet.js');
    exportWallet = walletMod.exportWallet;
    listWallets = walletMod.listWallets;
  } catch {
    return;
  }

  const wallets = listWallets();
  if (wallets.wallets.length === 0) return;

  const walletName = options.walletName || wallets.defaultWallet;
  if (!walletName) return;

  let exported;
  try {
    exported = exportWallet(walletName, password);
  } catch {
    return;
  }

  for (const req of ranked) {
    try {
      const sig = await buildPaymentForRequirement(req, exported, url);
      if (sig) yield { signature: sig, network: req.network };
    } catch {
      // This payment option failed to build, try next
      continue;
    }
  }
}

/**
 * Attempt to auto-pay a 402 response (single-shot, returns first viable signature).
 * For fallback support, use createPaymentSignatures() instead.
 *
 * @param {Response} response - The 402 HTTP response
 * @param {string} url - The original request URL
 * @param {object} options - { password, walletName }
 * @returns {string|null} Payment-Signature header value, or null if can't pay
 */
export async function createPaymentSignature(response, url, options = {}) {
  for await (const { signature } of createPaymentSignatures(response, url, options)) {
    return signature;
  }
  return null;
}
