---
name: nansen-trade
description: Execute DEX swaps on Solana or Base. Use when buying or selling a token, getting a swap quote, or executing a trade.
allowed-tools: Bash
---

# Trade

Two-step flow: quote then execute. **Trades are irreversible once on-chain.**

## Quote

```bash
nansen trade quote \
  --chain solana \
  --from So11111111111111111111111111111111111111112 \
  --to EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v \
  --amount 1000000000
```

## Execute

```bash
# Execute the best quote by ID
nansen trade execute --quote <quote-id>
```

> ⚠️ Quotes expire — if execute fails, get a fresh quote and retry.

## WalletConnect (EVM only)

```bash
nansen trade quote --chain base --from <addr> --to <addr> --amount <units> \
  --wallet walletconnect
nansen trade execute --quote <quote-id> --wallet wc
```

## Agent pattern

```bash
# Pipe quote ID directly into execute
nansen trade quote --chain solana --from <from> --to <to> --amount <amt> \
  --output json | jq -r '.data.quotes[0].id' \
  | xargs -I{} nansen trade execute --quote {}
```

## Common Token Addresses

| Token | Chain | Address |
|-------|-------|---------|
| SOL | Solana | `So11111111111111111111111111111111111111112` |
| USDC | Solana | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` |
| JUP | Solana | `JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN` |
| ETH | Base | `0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee` |
| USDC | Base | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |

## Amounts are in base units

| Token | Decimals | Example: 1 token |
|-------|----------|-----------------|
| SOL | 9 | `1000000000` |
| ETH | 18 | `1000000000000000000` |
| USDC | 6 | `1000000` |

## Flags

| Flag | Purpose |
|------|---------|
| `--chain` | `solana` or `base` |
| `--from` | Source token address |
| `--to` | Destination token address |
| `--amount` | Amount in base units |
| `--wallet wc` | Sign via WalletConnect (EVM only) |
| `--quote` | Quote ID from quote response |

## Exit Codes

`0`=Success, `1`=Error, `2`=Quote expired (re-run quote), `3`=Auth/wallet error
