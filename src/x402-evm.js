/**
 * Nansen CLI - x402 EVM Auto-Payment
 * Implements EIP-3009 TransferWithAuthorization via EIP-712 typed data signing.
 * Zero external dependencies — uses Node.js built-in crypto + wallet.js keccak256.
 */

import crypto from 'crypto';

// ============= Keccak-256 (inline from wallet.js PR #26) =============
// Needed for EIP-712 hashing. Once wallet.js lands, this can be imported instead.

const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [
   0,  1, 62, 28, 27, 36, 44,  6, 55, 20,
   3, 10, 43, 25, 39, 41, 45, 15, 21,  8,
  18,  2, 61, 56, 14,
];
const M = 0xffffffffffffffffn;

function rot64(v, r) {
  return r === 0 ? v : ((v << BigInt(r)) | (v >> BigInt(64 - r))) & M;
}

function keccakF(s) {
  for (let round = 0; round < 24; round++) {
    const c0 = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20];
    const c1 = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21];
    const c2 = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22];
    const c3 = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23];
    const c4 = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];
    const d0 = (c4 ^ rot64(c1, 1)) & M;
    const d1 = (c0 ^ rot64(c2, 1)) & M;
    const d2 = (c1 ^ rot64(c3, 1)) & M;
    const d3 = (c2 ^ rot64(c4, 1)) & M;
    const d4 = (c3 ^ rot64(c0, 1)) & M;
    for (let y = 0; y < 25; y += 5) {
      s[y]     = (s[y]     ^ d0) & M;
      s[y + 1] = (s[y + 1] ^ d1) & M;
      s[y + 2] = (s[y + 2] ^ d2) & M;
      s[y + 3] = (s[y + 3] ^ d3) & M;
      s[y + 4] = (s[y + 4] ^ d4) & M;
    }
    const t = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const src = x + 5 * y;
        const dst = y + 5 * ((2 * x + 3 * y) % 5);
        t[dst] = rot64(s[src], ROT[src]);
      }
    }
    for (let y = 0; y < 25; y += 5) {
      const t0 = t[y], t1 = t[y+1], t2 = t[y+2], t3 = t[y+3], t4 = t[y+4];
      s[y]   = (t0 ^ ((~t1 & M) & t2)) & M;
      s[y+1] = (t1 ^ ((~t2 & M) & t3)) & M;
      s[y+2] = (t2 ^ ((~t3 & M) & t4)) & M;
      s[y+3] = (t3 ^ ((~t4 & M) & t0)) & M;
      s[y+4] = (t4 ^ ((~t0 & M) & t1)) & M;
    }
    s[0] = (s[0] ^ RC[round]) & M;
  }
}

export function keccak256(input) {
  const rate = 136;
  const s = new Array(25).fill(0n);
  const blocks = Math.max(1, Math.ceil((input.length + 1) / rate));
  const padded = Buffer.alloc(blocks * rate);
  input.copy(padded);
  padded[input.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < 17; i++) {
      s[i] ^= padded.readBigUInt64LE(off + i * 8);
    }
    keccakF(s);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    out.writeBigUInt64LE(s[i] & M, i * 8);
  }
  return out;
}

// ============= EIP-712 Type Hashing =============

const DOMAIN_TYPES = [
  { name: 'name', type: 'string' },
  { name: 'version', type: 'string' },
  { name: 'chainId', type: 'uint256' },
  { name: 'verifyingContract', type: 'address' },
];

const AUTHORIZATION_TYPES = [
  { name: 'from', type: 'address' },
  { name: 'to', type: 'address' },
  { name: 'value', type: 'uint256' },
  { name: 'validAfter', type: 'uint256' },
  { name: 'validBefore', type: 'uint256' },
  { name: 'nonce', type: 'bytes32' },
];

/**
 * Encode a type string for EIP-712 typeHash.
 * e.g. "TransferWithAuthorization(address from,address to,uint256 value,...)"
 */
function encodeType(typeName, fields) {
  const fieldStrs = fields.map(f => `${f.type} ${f.name}`);
  return `${typeName}(${fieldStrs.join(',')})`;
}

/**
 * Compute typeHash = keccak256(encodeType(...))
 */
function typeHash(typeName, fields) {
  return keccak256(Buffer.from(encodeType(typeName, fields), 'utf8'));
}

/**
 * ABI-encode a single value to 32 bytes based on its EIP-712 type.
 */
function encodeValue(fieldType, value) {
  if (fieldType === 'string') {
    // Strings are hashed
    return keccak256(Buffer.from(value, 'utf8'));
  }
  if (fieldType === 'bytes') {
    const buf = typeof value === 'string' ? Buffer.from(value.replace(/^0x/, ''), 'hex') : value;
    return keccak256(buf);
  }
  if (fieldType === 'bytes32') {
    if (typeof value === 'string') {
      return Buffer.from(value.replace(/^0x/, ''), 'hex');
    }
    return value;
  }
  if (fieldType === 'address') {
    // Left-pad address to 32 bytes
    const addr = value.replace(/^0x/, '').toLowerCase();
    return Buffer.from(addr.padStart(64, '0'), 'hex');
  }
  if (fieldType.startsWith('uint') || fieldType.startsWith('int')) {
    // Encode as 32-byte big-endian
    const hex = BigInt(value).toString(16).padStart(64, '0');
    return Buffer.from(hex, 'hex');
  }
  if (fieldType === 'bool') {
    return Buffer.from((value ? '1' : '0').padStart(64, '0'), 'hex');
  }
  throw new Error(`Unsupported EIP-712 field type: ${fieldType}`);
}

/**
 * Compute struct hash = keccak256(typeHash || encodeValue(field1) || encodeValue(field2) || ...)
 */
function hashStruct(typeName, fields, data) {
  const parts = [typeHash(typeName, fields)];
  for (const field of fields) {
    const value = data[field.name];
    if (value === undefined || value === null) {
      throw new Error(`Missing EIP-712 field: ${field.name}`);
    }
    parts.push(encodeValue(field.type, value));
  }
  return keccak256(Buffer.concat(parts));
}

/**
 * Compute EIP-712 domain separator hash.
 */
function hashDomain(domain) {
  return hashStruct('EIP712Domain', DOMAIN_TYPES, domain);
}

/**
 * Compute EIP-712 final hash: keccak256("\x19\x01" || domainSeparator || structHash)
 */
export function hashTypedData(domain, primaryType, fields, message) {
  const domainSeparator = hashDomain(domain);
  const structHash = hashStruct(primaryType, fields, message);
  return keccak256(Buffer.concat([
    Buffer.from([0x19, 0x01]),
    domainSeparator,
    structHash,
  ]));
}

// ============= ECDSA Signing (secp256k1) =============

// secp256k1 curve parameters
const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function modInverse(a, m) {
  let [old_r, r] = [((a % m) + m) % m, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}

function pointAdd(x1, y1, x2, y2) {
  if (x1 === null) return [x2, y2];
  if (x2 === null) return [x1, y1];
  if (x1 === x2 && y1 === y2) {
    const lam = (3n * x1 * x1 * modInverse(2n * y1, P)) % P;
    const x3 = ((lam * lam - 2n * x1) % P + P) % P;
    const y3 = ((lam * (x1 - x3) - y1) % P + P) % P;
    return [x3, y3];
  }
  if (x1 === x2) return [null, null];
  const lam = (((y2 - y1) % P + P) * modInverse(((x2 - x1) % P + P) % P, P)) % P;
  const x3 = ((lam * lam - x1 - x2) % P + P) % P;
  const y3 = ((lam * (x1 - x3) - y1) % P + P) % P;
  return [x3, y3];
}

function pointMul(k, x, y) {
  let [rx, ry] = [null, null];
  let [qx, qy] = [x, y];
  while (k > 0n) {
    if (k & 1n) [rx, ry] = pointAdd(rx, ry, qx, qy);
    [qx, qy] = pointAdd(qx, qy, qx, qy);
    k >>= 1n;
  }
  return [rx, ry];
}

/**
 * RFC 6979 deterministic nonce generation for secp256k1.
 */
function rfc6979k(privKeyHex, msgHash) {
  const x = Buffer.from(privKeyHex, 'hex');
  let v = Buffer.alloc(32, 0x01);
  let k = Buffer.alloc(32, 0x00);
  k = crypto.createHmac('sha256', k).update(Buffer.concat([v, Buffer.from([0x00]), x, msgHash])).digest();
  v = crypto.createHmac('sha256', k).update(v).digest();
  k = crypto.createHmac('sha256', k).update(Buffer.concat([v, Buffer.from([0x01]), x, msgHash])).digest();
  v = crypto.createHmac('sha256', k).update(v).digest();
  while (true) {
    v = crypto.createHmac('sha256', k).update(v).digest();
    const candidate = BigInt('0x' + v.toString('hex'));
    if (candidate >= 1n && candidate < N) return candidate;
    k = crypto.createHmac('sha256', k).update(Buffer.concat([v, Buffer.from([0x00])])).digest();
    v = crypto.createHmac('sha256', k).update(v).digest();
  }
}

/**
 * Sign a 32-byte hash with secp256k1 ECDSA.
 * Pure implementation with RFC 6979 deterministic k and correct recovery ID.
 * Returns '0x' + r (32 bytes) + s (32 bytes) + v (1 byte, 27 or 28).
 */
export function signHash(msgHash, privateKeyHex) {
  const z = BigInt('0x' + msgHash.toString('hex'));
  const d = BigInt('0x' + privateKeyHex);
  const k = rfc6979k(privateKeyHex, msgHash);

  const [rx, ry] = pointMul(k, Gx, Gy);
  const r = rx % N;
  if (r === 0n) throw new Error('Invalid signature: r=0');

  let s = (modInverse(k, N) * ((z + r * d) % N)) % N;
  if (s === 0n) throw new Error('Invalid signature: s=0');

  // Recovery ID based on y-coordinate parity before normalization
  let recoveryId = (ry % 2n === 0n) ? 0 : 1;

  // Low-S normalization (EIP-2)
  if (s > N >> 1n) {
    s = N - s;
    recoveryId ^= 1;
  }

  const v = 27 + recoveryId;
  return '0x' + r.toString(16).padStart(64, '0') + s.toString(16).padStart(64, '0') + v.toString(16);
}

// ============= x402 EVM Payment =============

/**
 * Extract chain ID from CAIP-2 network identifier.
 * e.g. "eip155:8453" → 8453
 */
function getChainId(network) {
  const match = network.match(/^eip155:(\d+)$/);
  if (!match) throw new Error(`Invalid EVM network: ${network}`);
  return parseInt(match[1], 10);
}

/**
 * Create an x402 payment payload for EVM (EIP-3009 TransferWithAuthorization).
 *
 * @param {object} requirements - Parsed PaymentRequirements from 402 response
 * @param {string} privateKeyHex - 32-byte EVM private key as hex
 * @param {string} walletAddress - Signer's EVM address
 * @param {string} resource - Original request URL
 * @returns {string} Base64-encoded PaymentPayload for Payment-Signature header
 */
export function createEvmPaymentPayload(requirements, privateKeyHex, walletAddress, resource) {
  const chainId = getChainId(requirements.network);
  const extra = requirements.extra || {};

  // Token name and version from requirements.extra (set by server/facilitator)
  const tokenName = extra.name;
  const tokenVersion = extra.version || '1';

  if (!tokenName) {
    throw new Error('EIP-712 domain name missing from requirements.extra');
  }

  // Generate random nonce (32 bytes)
  const nonce = '0x' + crypto.randomBytes(32).toString('hex');

  // Validity window: valid now, expires in 1 hour
  const now = Math.floor(Date.now() / 1000);
  const validAfter = '0';
  const validBefore = String(now + 3600);

  // EIP-712 domain
  const domain = {
    name: tokenName,
    version: tokenVersion,
    chainId,
    verifyingContract: requirements.asset,
  };

  // EIP-3009 message
  const message = {
    from: walletAddress,
    to: requirements.pay_to || requirements.payTo,
    value: BigInt(requirements.amount),
    validAfter: BigInt(validAfter),
    validBefore: BigInt(validBefore),
    nonce: nonce,
  };

  // Hash and sign
  const msgHash = hashTypedData(domain, 'TransferWithAuthorization', AUTHORIZATION_TYPES, message);
  const signature = signHash(msgHash, privateKeyHex);

  // Build payload (camelCase keys per x402 spec)
  const payload = {
    x402Version: 2,
    payload: {
      authorization: {
        from: walletAddress,
        to: message.to,
        value: String(requirements.amount),
        validAfter: validAfter,
        validBefore: validBefore,
        nonce: nonce,
      },
      signature: signature,
    },
    accepted: requirements,
  };

  // Add resource as object if provided
  if (resource) {
    payload.resource = { url: resource };
  }

  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

/**
 * Check if a network string is an EVM network.
 */
export function isEvmNetwork(network) {
  return typeof network === 'string' && network.startsWith('eip155:');
}
