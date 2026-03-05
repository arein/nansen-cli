---
name: nansen-wallet-attribution
description: Cluster and attribute related wallets — funding chains, shared signers, CEX deposit patterns. Use when tracing wallet ownership, governance voters, or related address clusters.
metadata:
  openclaw:
    requires:
      env:
        - NANSEN_API_KEY
      bins:
        - nansen
    primaryEnv: NANSEN_API_KEY
    install:
      - kind: node
        package: nansen-cli
        bins: [nansen]
allowed-tools: Bash
---

# Wallet Clustering & Attribution

Run steps 1-3 on the seed. For every new address found, ask the human: **"Found `<addr>` via `<signal>` (`<label>`). Want me to query it?"** On confirm, re-run steps 1-3 on it. Keep expanding until no new addresses or confidence is Low.

```bash
# 1. Labels
nansen research profiler labels --address <addr> --chain ethereum

# 2. Related wallets (First Funder, Signer, Deployed via)
nansen research profiler related-wallets --address <addr> --chain ethereum

# 3. Counterparties — try 90d, then 365d if empty; repeat on each L2
nansen research profiler counterparties --address <addr> --chain ethereum --days 90
nansen research profiler counterparties --address <addr> --chain ethereum --days 365
for chain in base arbitrum optimism polygon; do
  nansen research profiler counterparties --address <addr> --chain $chain --days 365
done

# 4. Batch profile the cluster
nansen research profiler batch --addresses "<a1>,<a2>" --chain ethereum --include labels,balance,pnl

# 5. Compare pairs
nansen research profiler compare --addresses "<a1>,<a2>" --chain ethereum

# 6. Coordinated balance movements
nansen research profiler historical-balances --address <addr> --chain ethereum --days 90

# 7. Multi-hop trace — only if 2-3 inconclusive
nansen research profiler trace --address <addr> --chain ethereum --depth 2 --width 3
```

**Stop expanding when:** address is a known protocol/CEX · confidence is Low · already visited · cluster > 10 wallets.

## Attribution Rules

- CEX withdrawal → wallet owner (NOT the CEX)
- Smart account/DCA bot → end-user who funds it (NOT the protocol)
- Safe deployer ≠ owner — identical signer sets across Safes = same controller

| Confidence | Signals |
|------------|---------|
| **High** | First Funder / shared Safe signers / same CEX deposit address |
| **Medium** | Coordinated balance movements / related-wallets + label match |
| **Exclude** | ENS alone, single CEX withdrawal, single deployer |

**Output:** `address` · `owner` · `confidence (H/M/L)` · `signals` · `role`

**Notes:** Historical balances reveal past holdings on drained wallets — useful fingerprint. `trace` is credit-heavy; keep `--width 3` or lower.
