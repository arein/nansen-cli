---
name: nansen-wallet-attribution
description: "Cluster and attribute related wallets — funding chains, shared signers, CEX deposit patterns."
---

# Wallet Attribution

**Answers:** "Who controls this wallet? Are these wallets related?"

Chain: `0x` → `--chain ethereum` (also base, arbitrum, optimism, polygon). Base58 → `--chain solana`.

```bash
ADDR=<address> CHAIN=<ethereum|solana|base|...>  # detect from address format above
# 1. Identity
nansen research profiler labels --address $ADDR --chain $CHAIN
# 2. Related wallets (paginate with --page N)
nansen research profiler related-wallets --address $ADDR --chain $CHAIN
# 3. Counterparties (paginate with --page N; widen with --days 365 if empty)
nansen research profiler counterparties --address $ADDR --chain $CHAIN --days 90
# 4. Batch profile cluster
nansen research profiler batch --addresses "addr1,addr2" --chain $CHAIN --include labels,balance,pnl
# 5. Compare pairs → shared_counterparties, shared_tokens, balances
nansen research profiler compare --addresses "addr1,addr2" --chain $CHAIN
# 6. Historical balances (fingerprint drained wallets)
nansen research profiler historical-balances --address $ADDR --chain $CHAIN --days 90
# 7. Multi-hop trace (credit-heavy — keep --width ≤3)
nansen research profiler trace --address $ADDR --chain $CHAIN --depth 2 --width 3
```

See REFERENCE.md for expansion protocol, attribution rules, and confidence scoring.
