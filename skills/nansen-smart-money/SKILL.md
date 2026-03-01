---
name: nansen-smart-money
description: Smart money tracking — netflow, trades, holdings, DCAs, perp trades. Use when finding what smart money wallets are buying/selling or tracking whale activity.
allowed-tools: Bash
---

# Smart Money

```bash
# What is smart money buying on Solana right now?
nansen research smart-money netflow --chain solana --limit 10

# Smart money DEX trades (with label filter)
nansen research smart-money dex-trades --chain solana --labels "Smart Trader" --limit 20

# Top smart money holdings
nansen research smart-money holdings --chain solana --limit 10

# Jupiter DCA activity (Solana only, no --chain)
nansen research smart-money dcas --limit 10

# Hyperliquid perp trades (no --chain)
nansen research smart-money perp-trades --limit 10

# Historical holdings for a specific token
nansen research smart-money historical-holdings --chain solana --token-address <addr>
```

## Agent pattern

```bash
# JSON netflow with key fields only
nansen research smart-money netflow --chain solana --output json \
  --fields symbol,address,netflow_usd,smart_money_count
```

## Smart Money Labels

| Label | Description |
|-------|-------------|
| `Fund` | Crypto funds |
| `Smart Trader` | All-time top performers |
| `30D Smart Trader` | Top performers last 30 days |
| `90D Smart Trader` | Top performers last 90 days |
| `180D Smart Trader` | Top performers last 180 days |
| `Smart HL Perps Trader` | Top Hyperliquid perp traders |

## Flags

| Flag | Purpose |
|------|---------|
| `--chain` | Required for most (not perp/dca) |
| `--labels` | Filter by SM label (quoted if multi-word) |
| `--limit` | Number of results |
| `--output json` | JSON output |
| `--fields a,b` | Select fields |

## Exit Codes

`0`=Success, `1`=Error, `2`=No data for chain/label, `3`=Auth error
