---
"nansen-cli": minor
---

Restructure CLI into research/trade/wallet namespaces

- Commands reorganized: `smart-money`, `profiler`, `token`, `portfolio` now live under `nansen research`
- New `nansen trade` namespace for `quote` and `execute`
- New `nansen wallet` namespace for wallet management
- Old top-level commands still work with deprecation warnings
