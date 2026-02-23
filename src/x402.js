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
 * Find the best payment requirement we can fulfill.
 * Prefers EVM (gasless EIP-3009) over Solana (requires facilitator fee payer).
 */
function selectRequirement(requirements) {
  const evm = requirements.find(r => isEvmNetwork(r.network));
  if (evm) return evm;

  const svm = requirements.find(r => isSvmNetwork(r.network));
  if (svm) return svm;

  return null;
}

/**
 * Attempt to auto-pay a 402 response.
 *
 * @param {Response} response - The 402 HTTP response
 * @param {string} url - The original request URL
 * @param {object} options - { password, walletName }
 * @returns {string|null} Payment-Signature header value, or null if can't pay
 */
export async function createPaymentSignature(response, url, options = {}) {
  const requirements = parsePaymentRequirements(response);
  if (!requirements || requirements.length === 0) return null;

  const requirement = selectRequirement(requirements);
  if (!requirement) return null;

  // Get wallet — dynamically import wallet.js (from PR #26)
  const password = options.password || process.env.NANSEN_WALLET_PASSWORD;
  if (!password) return null;

  let exportWallet, listWallets;
  try {
    const walletMod = await import('./wallet.js');
    exportWallet = walletMod.exportWallet;
    listWallets = walletMod.listWallets;
  } catch {
    // wallet.js not available (PR #26 not merged yet)
    return null;
  }

  const wallets = listWallets();
  if (wallets.wallets.length === 0) return null;

  const walletName = options.walletName || wallets.defaultWallet;
  if (!walletName) return null;

  try {
    const exported = exportWallet(walletName, password);

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
  } catch (err) {
    // Wallet decrypt failed or signing failed
    return null;
  }
}
