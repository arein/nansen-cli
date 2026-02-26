/**
 * WalletConnect Trading & Transfer Support
 *
 * Allows signing and broadcasting transactions via a WalletConnect-connected wallet
 * (hardware wallets, mobile wallets) instead of local key storage.
 * Uses the walletconnect CLI binary (subprocess-based, same as x402).
 *
 * EVM only — Solana via WalletConnect is not supported.
 */

import { exec } from './walletconnect-exec.js';

/**
 * Get the address of the connected WalletConnect wallet.
 * Returns the first account address, or null if not connected / binary missing.
 */
export async function getWalletConnectAddress() {
  try {
    const output = await exec('walletconnect', ['whoami', '--json'], 3000);
    const data = JSON.parse(output);
    if (data.connected === false) return null;
    return data.accounts?.[0]?.address || null;
  } catch {
    return null;
  }
}

/**
 * Send a transaction via WalletConnect.
 *
 * The connected wallet signs and may broadcast the transaction.
 * Returns either { txHash } (wallet broadcast) or { signedTransaction } (we broadcast).
 *
 * @param {object} txData - Transaction data: { to, data, value, gas, chainId }
 * @param {number} [timeoutMs=120000] - Timeout for user approval
 * @returns {{ txHash?: string, signedTransaction?: string }}
 */
export async function sendTransactionViaWalletConnect(txData, timeoutMs = 120000) {
  // The walletconnect CLI expects chainId as "eip155:<id>" string format
  const chainId = txData.chainId
    ? (String(txData.chainId).startsWith('eip155:') ? txData.chainId : `eip155:${txData.chainId}`)
    : undefined;

  const payload = {
    to: txData.to,
    data: txData.data || '0x',
    value: txData.value ? '0x' + BigInt(txData.value).toString(16) : '0x0',
    gas: txData.gas ? '0x' + BigInt(txData.gas).toString(16) : undefined,
    chainId,
  };

  const output = await exec('walletconnect', ['send-transaction', JSON.stringify(payload)], timeoutMs);

  // walletconnect may print status messages before the JSON line — extract JSON only
  const jsonLine = output.split('\n').find(line => line.startsWith('{'));
  if (!jsonLine) throw new Error('No JSON output from walletconnect send-transaction');
  const result = JSON.parse(jsonLine);

  // The CLI returns { transactionHash: "0x..." }
  if (result.transactionHash) return { txHash: result.transactionHash };
  if (result.txHash) return { txHash: result.txHash };
  if (result.signedTransaction) return { signedTransaction: result.signedTransaction };

  throw new Error('Unexpected response from walletconnect send-transaction');
}

/**
 * Send an ERC-20 approval via WalletConnect.
 *
 * Builds approve(spender, MAX_UINT256) calldata and delegates to sendTransactionViaWalletConnect.
 *
 * @param {string} tokenAddress - ERC-20 token contract
 * @param {string} spenderAddress - Approval target (e.g. DEX router)
 * @param {number} chainId - EIP-155 chain ID
 * @returns {{ txHash?: string, signedTransaction?: string }}
 */
export async function sendApprovalViaWalletConnect(tokenAddress, spenderAddress, chainId) {
  // ERC-20 approve(address spender, uint256 amount) selector = 0x095ea7b3
  const MAX_UINT256_HEX = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
  const data = '0x095ea7b3'
    + spenderAddress.slice(2).toLowerCase().padStart(64, '0')
    + MAX_UINT256_HEX;

  return sendTransactionViaWalletConnect({
    to: tokenAddress,
    data,
    value: '0',
    gas: '100000',
    chainId,
  });
}
