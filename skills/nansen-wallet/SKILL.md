---
name: nansen-wallet
description: Wallet management — create, list, send native tokens. Use when creating a new wallet, listing existing wallets, or sending tokens.
allowed-tools: Bash
---

# Wallet

## Create

```bash
# Interactive
nansen wallet create

# Non-interactive (for agents)
NANSEN_WALLET_PASSWORD="<your-password>" nansen wallet create
```

## List

```bash
nansen wallet list
```

## Send

```bash
# Send native token
nansen wallet send --to <addr> --amount 1.5 --chain evm

# Send entire balance
nansen wallet send --to <addr> --chain evm --max

# Send via WalletConnect (EVM only)
nansen wallet send --to <addr> --amount 1.5 --chain base --wallet walletconnect
```

## Auth Setup

**x402 Pay-Per-Call (no API key needed):**
```bash
nansen wallet create                        # Generate EVM + Solana keypair
# Fund the EVM address with USDC on Base (~$0.50 minimum)
export NANSEN_WALLET_PASSWORD="<your-password>"   # Skip interactive prompt
# Done — CLI auto-pays $0.01-$0.05 per call
```

**API Key:**
```bash
export NANSEN_API_KEY=your-api-key
# Or: nansen login --api-key YOUR_KEY
```

## Flags

| Flag | Purpose |
|------|---------|
| `--to` | Recipient address |
| `--amount` | Amount to send |
| `--chain` | `evm` or `solana` |
| `--max` | Send entire balance |
| `--wallet wc` | Sign via WalletConnect (EVM only) |

## Exit Codes

`0`=Success, `1`=Error, `2`=Insufficient balance, `3`=Auth/decrypt error
