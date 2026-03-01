---
name: nansen-search
description: Search for tokens, wallets, or entities by name or address. Use when you have a token name and need the full address, or want to find an entity.
allowed-tools: Bash
---

# Search

```bash
# Search for a token by name
nansen research search "jupiter" --type token

# Search for an entity / person
nansen research search "Vitalik" --type entity --limit 5

# Lookup by address
nansen research search "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

# Agent pattern — get token address from name
nansen research search "bonk" --type token --output json \
  --fields address,name,symbol,chain
```

## Tips

- Search is case-insensitive
- Use `--type token` to filter to tokens only, `--type entity` for wallets/people
- After getting an address, use `nansen-token` or `nansen-profiler` for full analysis
- `nansen schema` lists all available commands and return fields

## Flags

| Flag | Purpose |
|------|---------|
| `--type` | Filter: `token` or `entity` |
| `--limit` | Number of results (default 10) |
| `--output json` | JSON output |
| `--fields a,b` | Select fields |

## Exit Codes

`0`=Success, `1`=Error, `2`=No results found, `3`=Auth error
