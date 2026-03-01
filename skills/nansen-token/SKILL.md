---
name: nansen-token
description: Token analytics — price, holders, flows, screener, PnL, DEX trades. Use when researching a specific token, checking smart money holders, or screening trending tokens.
allowed-tools: Bash
---

# Token Analytics

`--chain` required. Use `--token` for the token address. Native tokens (SOL, ETH) not supported on most endpoints — use wrapped addresses.

## Screener

```bash
# Top tokens by smart money activity
nansen research token screener --chain solana --timeframe 24h --smart-money --limit 20

# Agent pattern — JSON with selected fields
nansen research token screener --chain solana --timeframe 24h --output json \
  --fields symbol,address,price_usd,smart_money_netflow_usd
```

## Token Info & Indicators

```bash
nansen research token info --token <addr> --chain solana
nansen research token indicators --token <addr> --chain solana
```

## Price (OHLCV)

```bash
nansen research token ohlcv --token <addr> --chain solana --timeframe 1h --limit 24
```

## Holders

```bash
nansen research token holders --token <addr> --chain solana --smart-money
```

## Flows

```bash
nansen research token flows --token <addr> --chain solana --days 7
nansen research token flow-intelligence --token <addr> --chain solana
nansen research token who-bought-sold --token <addr> --chain solana
```

## DEX Trades & PnL

```bash
nansen research token dex-trades --token <addr> --chain solana --limit 20
nansen research token pnl --token <addr> --chain solana --sort total_pnl_usd:desc
nansen research token transfers --token <addr> --chain solana --enrich
```

## Perps & DCA (no --chain)

```bash
nansen research token perp-trades --symbol ETH --days 7
nansen research token perp-positions --symbol BTC
nansen research token perp-pnl-leaderboard --symbol SOL
nansen research token jup-dca --token <addr>
```

## Flags

| Flag | Purpose |
|------|---------|
| `--chain` | Required (ethereum, solana, base, etc.) |
| `--token` | Token address (alias: `--mint`, `--token-address`) |
| `--timeframe` | OHLCV interval (1h, 4h, 1d) |
| `--smart-money` | Filter to smart money wallets only |
| `--days` | Lookback period (default 30) |
| `--sort field:dir` | Sort (e.g. `total_pnl_usd:desc`) |
| `--output json` | JSON output for parsing |
| `--fields a,b` | Return only specific fields |

## Exit Codes

`0`=Success, `1`=Error, `2`=Token not found, `3`=Auth error
