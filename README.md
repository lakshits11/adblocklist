# adblocklist

# Combined Blocklist (OISD + HaGeZi)

Automatically merged and deduplicated combination of two of the best DNS blocklists:

| Source | Description |
|--------|-------------|
| [OISD Big](https://oisd.nl) | ~280k entries — "Block. Don't break." |
| [HaGeZi Pro++](https://github.com/hagezi/dns-blocklists) | ~230k entries — Aggressive blocking |

The merged list removes all duplicate entries across both lists.

## 📋 Subscribe in uBlock Origin

**Raw link (use this):**

```
https://raw.githubusercontent.com/lakshits11/adblocklist/main/blocklist.txt
```

### How to add in uBlock Origin:
1. Open uBlock Origin **Dashboard** → **Filter lists** tab
2. Scroll to the bottom → **Import...** (or "Custom" section)
3. Paste the raw link above
4. Click **Apply changes**

## ⚙️ How it works

- A GitHub Actions workflow runs **every 12 hours**
- It downloads both source lists
- A Python script **merges** them and **removes duplicates**
- The result is committed to this repo as `blocklist.txt`
- uBlock Origin fetches the updated list automatically

## 🔗 Permanent Link

The blocklist URL **never changes**. uBlock Origin will auto-update.

## 📊 Stats

Stats are printed in the [Actions log](../../actions) for each run and embedded
in the header of `blocklist.txt`.

## License

This project merges third-party lists. Refer to the original licenses:
- [OISD License](https://github.com/sjhgvr/oisd/blob/main/LICENSE)
- [HaGeZi License](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE)
