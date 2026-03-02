---
"nansen-cli": patch
---

fix: correct `--date` option marked as `required: true` when it is optional

The schema incorrectly marked `--date` as `required: true` for three commands:
- `research token flows`
- `research token who-bought-sold`
- `research profiler transactions`

All three use `parseDateOption` with a `days` fallback, so `--date` is optional — omitting it defaults to a rolling window based on `--days`. An agent following the schema strictly would unnecessarily refuse to run these commands without a date.
