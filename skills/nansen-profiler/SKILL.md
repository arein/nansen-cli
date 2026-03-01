---
name: nansen-profiler
description: Wallet profiler — balance, PnL, labels, transactions, counterparties, related wallets. Use when analysing a specific wallet address or comparing wallets.
allowed-tools: Bash
---

# Wallet Profiler

`--chain` and `--address` required for most commands.

## Balance & Identity

```bash
nansen research profiler balance --address <addr> --chain solana
nansen research profiler labels --address <addr> --chain ethereum
nansen research profiler search --query "Vitalik"
```

## PnL

```bash
nansen research profiler pnl --address <addr> --chain ethereum --days 30
nansen research profiler pnl-summary --address <addr> --chain ethereum
```

## Transactions & History

```bash
nansen research profiler transactions --address <addr> --chain ethereum --limit 20
nansen research profiler historical-balances --address <addr> --chain solana --days 30
```

## Relationships

```bash
nansen research profiler related-wallets --address <addr> --chain ethereum
nansen research profiler counterparties --address <addr> --chain ethereum
```

## Perps (no --chain)

```bash
nansen research profiler perp-positions --address <addr>
nansen research profiler perp-trades --address <addr>
```

## Batch & Compare

```bash
# Batch — multiple wallets at once
nansen research profiler batch \
  --addresses "0xabc,0xdef" --chain ethereum \
  --include labels,balance,pnl

# Compare two wallets
nansen research profiler compare --addresses "0xabc,0xdef" --chain ethereum

# Trace fund flows (⚠️ makes N×width API calls — can burn credits fast)
nansen research profiler trace --address <addr> --chain ethereum --depth 2 --width 5
```

## Agent pattern

```bash
# Full wallet snapshot in one call
nansen research profiler batch --addresses "<addr>" --chain solana \
  --include labels,balance,pnl --output json
```

## Flags

| Flag | Purpose |
|------|---------|
| `--address` | Wallet address |
| `--chain` | Required (not for perps/search) |
| `--days` | Lookback period (default 30) |
| `--include` | Batch fields: labels,balance,pnl |
| `--depth` | Trace depth (default 2) |
| `--width` | Trace width — keep low to save credits |

## Exit Codes

`0`=Success, `1`=Error, `2`=Wallet not found / no data, `3`=Auth error
