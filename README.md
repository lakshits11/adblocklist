# Combined Blocklists

Auto-merged and deduplicated combination of top DNS blocklists.

## 🔗 Subscribe — Pick any mirror

| Mirror | URL | Speed |
|--------|-----|-------|
| **jsDelivr CDN** (recommended) | `https://cdn.jsdelivr.net/gh/lakshits11/adblocklist@main/blocklist.txt` | ⚡ Fastest |
| GitHub raw | `https://raw.githubusercontent.com/lakshits11/adblocklist/main/blocklist.txt` | 🟢 Fast |

### How to add in uBlock Origin:
1. Open uBlock Origin **Dashboard** → **Filter lists**
2. Scroll to bottom → **Import...**
3. Paste any URL above
4. Click **Apply changes**

## ⚙️ How it works

```
Every 24 hours:
  GitHub Actions runs
    → Downloads all source lists (parallel, streaming)
    → Merges into single set (deduplicates)
    → Writes blocklist.txt
    → Commits to repo
    → Purges CDN cache
```

Stats are embedded in the header of `blocklist.txt` after each build.
