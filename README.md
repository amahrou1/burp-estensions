# JWT Extractor — Burp Suite Extension

A Jython-based Burp Suite extension that extracts JWTs, API keys, and other secrets from HTTP responses. Works with **Burp Suite Community Edition**.

## What It Extracts

| Pattern | Example |
|---------|---------|
| **JWT** | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw...` |
| **AWS Access Key** | `AKIAIOSFODNN7EXAMPLE` |
| **Google API Key** | `AIzaSyA-random-key-value-here123456` |
| **GitHub Token** | `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| **Slack Token** | `xoxb-xxxxxxxxxxxx-xxxxxxxxxxxx` |
| **Bearer Token** | `Bearer eyJhbGciOiJIUzI1NiJ9...` |

Adding a new pattern is a one-line change in `regex_engine.py` — no other file needs modification.

## Features

- **Context menu integration** — right-click any request(s) and select "Send to JWT Extractor"
- **Smart filtering** — only scans text-based responses (HTML, JS, JSON, XML), skips binaries
- **Deduplication** — same token from multiple endpoints is stored once, all source URLs tracked
- **JWT decoding** — decoded header and payload displayed as pretty-printed JSON
- **Export** — save findings as JSON or CSV
- **Copy to clipboard** — one-click copy of any token

## Prerequisites

1. **Burp Suite Community Edition** (or Professional)
   — Download from https://portswigger.net/burp/communitydownload

2. **Jython Standalone JAR**
   — Download from https://www.jython.org/download
   — You need the **standalone** JAR (e.g. `jython-standalone-2.7.3.jar`)

## Installation

### Step 1: Configure Jython in Burp

1. Open Burp Suite
2. Go to **Extensions** > **Extensions settings** (or **Extender** > **Options** in older versions)
3. Under **Python environment**, click **Select file** next to "Location of Jython standalone JAR file"
4. Browse to your downloaded `jython-standalone-2.7.x.jar` and select it

### Step 2: Load the Extension

1. Go to **Extensions** > **Installed** (or **Extender** > **Extensions**)
2. Click **Add**
3. Set **Extension type** to **Python**
4. Click **Select file** and choose `extractor.py` from this repository
5. Click **Next**

You should see `JWT Extractor loaded successfully.` in the output panel and a new **"JWT Extractor"** tab in Burp.

## Usage

### Scanning for Secrets

1. Browse your target through Burp's proxy or load requests into the Target/Proxy tabs
2. Select one or more requests in Proxy History, Site Map, or any message viewer
3. **Right-click** > **Send to JWT Extractor**
4. The extension scans the HTTP responses and displays findings in the JWT Extractor tab

### Viewing Results

- **Top pane** — table of all findings (token preview, pattern type, source URL, timestamp)
- **Bottom pane** — click any row to see the full token and decoded JWT details (header, payload, signature)

### Buttons

| Button | Action |
|--------|--------|
| **Clear All** | Remove all findings |
| **Copy Token** | Copy the selected token to clipboard |
| **Export JSON** | Save all findings to a `.json` file |
| **Export CSV** | Save all findings to a `.csv` file |

## Project Structure

```
extractor.py        # Entry point — IBurpExtender, IContextMenuFactory, ITab
regex_engine.py     # Pattern registry and scan logic
results_store.py    # Findings storage, deduplication, export
ui_panel.py         # Swing UI — JTable, detail pane, buttons
jwt_utils.py        # Base64URL decode, JWT validation helpers
```

## Adding New Patterns

Open `regex_engine.py` and append a dict to the `patterns` list:

```python
patterns = [
    # ... existing patterns ...
    {
        "name": "Stripe Secret Key",
        "pattern": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "validator": None,
    },
]
```

That's it. The engine, store, and UI pick up new patterns automatically.

## Troubleshooting

### Extension fails to load
- Make sure Jython standalone JAR is configured (see Step 1 above)
- Check the **Errors** tab under Extensions for stack traces

### No findings after scanning
- Verify the target responses contain text content (not just images/binaries)
- Check Burp's **Output** tab for scan summary messages
- Try scanning a request whose response you know contains a JWT

### "Module not found" errors
- Make sure all five `.py` files are in the **same directory**
- `extractor.py` automatically adds its own directory to `sys.path`

## License

Provided as-is for educational and authorized security testing purposes.
