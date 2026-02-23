/**
 * Tests for x402 EVM payment module
 */

import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import { hashTypedData, signHash, createEvmPaymentPayload, isEvmNetwork, keccak256 } from '../x402-evm.js';

// Inline EVM wallet generation (from wallet.js PR #26, not yet merged)
function generateEvmWallet() {
  const privateKey = crypto.randomBytes(32);
  const ecdh = crypto.createECDH('secp256k1');
  ecdh.setPrivateKey(privateKey);
  const publicKey = ecdh.getPublicKey(null, 'uncompressed');
  const hash = keccak256(publicKey.subarray(1));
  const addressBytes = hash.subarray(12);
  const addressHex = addressBytes.toString('hex');
  const addressHash = keccak256(Buffer.from(addressHex, 'utf8')).toString('hex');
  let checksummed = '0x';
  for (let i = 0; i < 40; i++) {
    checksummed += parseInt(addressHash[i], 16) >= 8
      ? addressHex[i].toUpperCase()
      : addressHex[i];
  }
  return { privateKey: privateKey.toString('hex'), address: checksummed };
}

describe('EIP-712 hashTypedData', () => {
  it('should produce a 32-byte hash', () => {
    const domain = {
      name: 'USD Coin',
      version: '2',
      chainId: 8453,
      verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    };

    const fields = [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'validAfter', type: 'uint256' },
      { name: 'validBefore', type: 'uint256' },
      { name: 'nonce', type: 'bytes32' },
    ];

    const message = {
      from: '0x1234567890abcdef1234567890abcdef12345678',
      to: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
      value: 50000n,
      validAfter: 0n,
      validBefore: BigInt(Math.floor(Date.now() / 1000) + 3600),
      nonce: '0x' + crypto.randomBytes(32).toString('hex'),
    };

    const hash = hashTypedData(domain, 'TransferWithAuthorization', fields, message);
    expect(hash).toBeInstanceOf(Buffer);
    expect(hash.length).toBe(32);
  });

  it('should produce different hashes for different messages', () => {
    const domain = {
      name: 'Test Token',
      version: '1',
      chainId: 1,
      verifyingContract: '0x0000000000000000000000000000000000000001',
    };

    const fields = [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'validAfter', type: 'uint256' },
      { name: 'validBefore', type: 'uint256' },
      { name: 'nonce', type: 'bytes32' },
    ];

    const msg1 = {
      from: '0x1111111111111111111111111111111111111111',
      to: '0x2222222222222222222222222222222222222222',
      value: 100n,
      validAfter: 0n,
      validBefore: 9999999999n,
      nonce: '0x' + '00'.repeat(32),
    };

    const msg2 = { ...msg1, value: 200n };

    const hash1 = hashTypedData(domain, 'TransferWithAuthorization', fields, msg1);
    const hash2 = hashTypedData(domain, 'TransferWithAuthorization', fields, msg2);
    expect(hash1.toString('hex')).not.toBe(hash2.toString('hex'));
  });
});

describe('signHash', () => {
  it('should produce a 65-byte hex signature (with 0x prefix)', () => {
    const wallet = generateEvmWallet();
    const msgHash = crypto.randomBytes(32);
    const sig = signHash(msgHash, wallet.privateKey);

    expect(sig).toMatch(/^0x[0-9a-f]{130}$/); // 0x + 65 bytes (130 hex chars)
  });

  it('should produce v=27 or v=28', () => {
    const wallet = generateEvmWallet();
    const msgHash = crypto.randomBytes(32);
    const sig = signHash(msgHash, wallet.privateKey);

    const v = parseInt(sig.slice(-2), 16);
    expect([27, 28]).toContain(v);
  });

  it('should produce different signatures for different messages', () => {
    const wallet = generateEvmWallet();
    const sig1 = signHash(crypto.randomBytes(32), wallet.privateKey);
    const sig2 = signHash(crypto.randomBytes(32), wallet.privateKey);
    expect(sig1).not.toBe(sig2);
  });
});

describe('createEvmPaymentPayload', () => {
  it('should create a valid base64-encoded payload', () => {
    const wallet = generateEvmWallet();
    const requirements = {
      scheme: 'exact',
      network: 'eip155:8453',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      amount: '50000',
      pay_to: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
      extra: { name: 'USD Coin', version: '2' },
    };

    const result = createEvmPaymentPayload(
      requirements,
      wallet.privateKey,
      wallet.address,
      'https://api.nansen.ai/v1/test',
    );

    // Should be valid base64
    const decoded = JSON.parse(Buffer.from(result, 'base64').toString('utf8'));
    expect(decoded.x402Version).toBe(2);
    expect(decoded.accepted.scheme).toBe('exact');
    expect(decoded.accepted.network).toBe('eip155:8453');
    expect(decoded.payload.authorization).toBeDefined();
    expect(decoded.payload.authorization.from).toBe(wallet.address);
    expect(decoded.payload.signature).toMatch(/^0x/);
    expect(decoded.resource.url).toBe('https://api.nansen.ai/v1/test');
  });

  it('should throw if extra.name is missing', () => {
    const wallet = generateEvmWallet();
    const requirements = {
      network: 'eip155:8453',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      amount: '50000',
      pay_to: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
      extra: {},
    };

    expect(() => createEvmPaymentPayload(
      requirements, wallet.privateKey, wallet.address, 'https://test.com',
    )).toThrow('name missing');
  });
});

describe('isEvmNetwork', () => {
  it('should return true for EVM networks', () => {
    expect(isEvmNetwork('eip155:8453')).toBe(true);
    expect(isEvmNetwork('eip155:1')).toBe(true);
  });

  it('should return false for non-EVM networks', () => {
    expect(isEvmNetwork('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp')).toBe(false);
    expect(isEvmNetwork('')).toBe(false);
    expect(isEvmNetwork(null)).toBe(false);
  });
});
