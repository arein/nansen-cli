/**
 * Tests for walletconnect-trading module
 *
 * Covers: getWalletConnectAddress, sendTransactionViaWalletConnect, sendApprovalViaWalletConnect
 * All subprocess calls are mocked via vi.mock('child_process').
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock child_process before importing the module
vi.mock('child_process', () => ({
  execFile: vi.fn(),
}));

import { execFile } from 'child_process';
import {
  getWalletConnectAddress,
  sendTransactionViaWalletConnect,
  sendApprovalViaWalletConnect,
} from '../walletconnect-trading.js';

function mockExecFile(stdout, err = null) {
  execFile.mockImplementation((cmd, args, opts, cb) => {
    if (err) {
      cb(err, '', '');
    } else {
      cb(null, stdout, '');
    }
  });
}

beforeEach(() => {
  vi.clearAllMocks();
});

// ============= getWalletConnectAddress =============

describe('getWalletConnectAddress', () => {
  it('returns address when connected', async () => {
    mockExecFile(JSON.stringify({
      connected: true,
      accounts: [{ address: '0x742d35Cc6bF4F3f4e0e3a8DD7e37ff4e4Be4E4B4' }],
    }));

    const address = await getWalletConnectAddress();
    expect(address).toBe('0x742d35Cc6bF4F3f4e0e3a8DD7e37ff4e4Be4E4B4');
    expect(execFile).toHaveBeenCalledWith('walletconnect', ['whoami', '--json'], expect.any(Object), expect.any(Function));
  });

  it('returns null when not connected', async () => {
    mockExecFile(JSON.stringify({ connected: false }));

    const address = await getWalletConnectAddress();
    expect(address).toBeNull();
  });

  it('returns null when no accounts', async () => {
    mockExecFile(JSON.stringify({ connected: true, accounts: [] }));

    const address = await getWalletConnectAddress();
    expect(address).toBeNull();
  });

  it('returns null on ENOENT (binary not found)', async () => {
    const err = new Error('spawn walletconnect ENOENT');
    err.code = 'ENOENT';
    mockExecFile('', err);

    const address = await getWalletConnectAddress();
    expect(address).toBeNull();
  });

  it('returns null on timeout', async () => {
    mockExecFile('', new Error('Command timed out'));

    const address = await getWalletConnectAddress();
    expect(address).toBeNull();
  });
});

// ============= sendTransactionViaWalletConnect =============

describe('sendTransactionViaWalletConnect', () => {
  it('sends correct JSON payload and returns txHash', async () => {
    mockExecFile(JSON.stringify({ txHash: '0xabc123' }));

    const result = await sendTransactionViaWalletConnect({
      to: '0x1234567890123456789012345678901234567890',
      data: '0xdeadbeef',
      value: '1000000000000000000', // 1 ETH in wei
      gas: '21000',
      chainId: 8453,
    });

    expect(result).toEqual({ txHash: '0xabc123' });

    // Verify the command arguments
    expect(execFile).toHaveBeenCalledWith(
      'walletconnect',
      ['send-transaction', expect.any(String)],
      expect.objectContaining({ timeout: 120000 }),
      expect.any(Function),
    );

    // Verify the JSON payload
    const payload = JSON.parse(execFile.mock.calls[0][1][1]);
    expect(payload.to).toBe('0x1234567890123456789012345678901234567890');
    expect(payload.data).toBe('0xdeadbeef');
    expect(payload.value).toBe('0xde0b6b3a7640000'); // 1 ETH in hex
    expect(payload.gas).toBe('0x5208'); // 21000 in hex
    expect(payload.chainId).toBe('eip155:8453');
  });

  it('handles transactionHash response from CLI', async () => {
    mockExecFile(JSON.stringify({ transactionHash: '0xtxhash123' }));

    const result = await sendTransactionViaWalletConnect({
      to: '0x1234567890123456789012345678901234567890',
      value: '0',
      chainId: 1,
    });

    expect(result).toEqual({ txHash: '0xtxhash123' });
  });

  it('passes through eip155: prefixed chainId', async () => {
    mockExecFile(JSON.stringify({ transactionHash: '0xabc' }));

    await sendTransactionViaWalletConnect({
      to: '0x1234567890123456789012345678901234567890',
      value: '0',
      chainId: 'eip155:10',
    });

    const payload = JSON.parse(execFile.mock.calls[0][1][1]);
    expect(payload.chainId).toBe('eip155:10');
  });

  it('handles signedTransaction response', async () => {
    mockExecFile(JSON.stringify({ signedTransaction: '0xf86c...' }));

    const result = await sendTransactionViaWalletConnect({
      to: '0x1234567890123456789012345678901234567890',
      value: '0',
      chainId: 1,
    });

    expect(result).toEqual({ signedTransaction: '0xf86c...' });
  });

  it('handles status messages before JSON output', async () => {
    mockExecFile('Connecting to wallet...\nWaiting for approval...\n' + JSON.stringify({ txHash: '0xdef456' }));

    const result = await sendTransactionViaWalletConnect({
      to: '0x1234567890123456789012345678901234567890',
      value: '0',
      chainId: 1,
    });

    expect(result).toEqual({ txHash: '0xdef456' });
  });

  it('converts value to hex correctly for zero', async () => {
    mockExecFile(JSON.stringify({ txHash: '0xabc' }));

    await sendTransactionViaWalletConnect({
      to: '0x1234567890123456789012345678901234567890',
      value: '0',
      chainId: 1,
    });

    const payload = JSON.parse(execFile.mock.calls[0][1][1]);
    expect(payload.value).toBe('0x0');
  });

  it('omits gas when not provided', async () => {
    mockExecFile(JSON.stringify({ txHash: '0xabc' }));

    await sendTransactionViaWalletConnect({
      to: '0x1234567890123456789012345678901234567890',
      value: '0',
      chainId: 1,
    });

    const payload = JSON.parse(execFile.mock.calls[0][1][1]);
    expect(payload.gas).toBeUndefined();
  });

  it('throws on timeout', async () => {
    mockExecFile('', new Error('Command timed out'));

    await expect(sendTransactionViaWalletConnect({
      to: '0x1234567890123456789012345678901234567890',
      value: '0',
      chainId: 1,
    })).rejects.toThrow('Command timed out');
  });

  it('throws when no JSON output', async () => {
    mockExecFile('Some non-JSON output');

    await expect(sendTransactionViaWalletConnect({
      to: '0x1234567890123456789012345678901234567890',
      value: '0',
      chainId: 1,
    })).rejects.toThrow('No JSON output');
  });

  it('uses custom timeout', async () => {
    mockExecFile(JSON.stringify({ txHash: '0xabc' }));

    await sendTransactionViaWalletConnect({
      to: '0x1234567890123456789012345678901234567890',
      value: '0',
      chainId: 1,
    }, 60000);

    expect(execFile).toHaveBeenCalledWith(
      'walletconnect',
      expect.any(Array),
      expect.objectContaining({ timeout: 60000 }),
      expect.any(Function),
    );
  });
});

// ============= sendApprovalViaWalletConnect =============

describe('sendApprovalViaWalletConnect', () => {
  it('builds correct approve calldata', async () => {
    mockExecFile(JSON.stringify({ txHash: '0xapproval123' }));

    const result = await sendApprovalViaWalletConnect(
      '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
      '0xDef1C0ded9bec7F1a1670819833240f027b25EfF', // 0x router
      8453, // Base
    );

    expect(result).toEqual({ txHash: '0xapproval123' });

    const payload = JSON.parse(execFile.mock.calls[0][1][1]);
    expect(payload.to).toBe('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48');
    expect(payload.chainId).toBe('eip155:8453');
    expect(payload.value).toBe('0x0');

    // Verify approve(address, uint256) calldata
    const data = payload.data;
    expect(data).toMatch(/^0x095ea7b3/); // approve selector
    // spender address padded to 32 bytes
    expect(data.slice(10, 74)).toBe('def1c0ded9bec7f1a1670819833240f027b25eff'.padStart(64, '0'));
    // max uint256
    expect(data.slice(74)).toBe('f'.repeat(64));
  });

  it('sends with gas limit of 100000', async () => {
    mockExecFile(JSON.stringify({ txHash: '0xabc' }));

    await sendApprovalViaWalletConnect(
      '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
      '0xDef1C0ded9bec7F1a1670819833240f027b25EfF',
      1,
    );

    const payload = JSON.parse(execFile.mock.calls[0][1][1]);
    expect(payload.gas).toBe('0x186a0'); // 100000 in hex
  });
});
