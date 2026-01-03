# Burp Link Extractor Extension

A powerful Burp Suite extension that automatically extracts all links and endpoints from HTTP responses. Works with Burp Suite Community Edition!

## Features

✅ **Automatic Link Extraction** - Captures links from all HTTP traffic automatically
✅ **Absolute URLs** - Extracts all `http://` and `https://` URLs
✅ **Relative Paths** - Finds endpoints like `/api/users` and converts them to absolute URLs
✅ **Smart Endpoint Detection** - Detects patterns like `Method="GET" "/users/login"`
✅ **Deduplication** - Removes duplicate links globally (only shows unique URLs)
✅ **Scope Filter** - Option to only capture in-scope URLs
✅ **Export Functionality** - Save all discovered links to a text file
✅ **Clean UI** - LinkFinder-style display in a separate Burp tab

---

## Installation Guide

### Prerequisites

1. **Burp Suite Community Edition** (or Professional)
   - Download from: https://portswigger.net/burp/communitydownload

2. **Java Development Kit (JDK)**
   - Download JDK 8 or higher from: https://adoptium.net/
   - Verify installation: `java -version`

### Step 1: Download Burp API

You need the Burp Extender API JAR file to compile the extension.

1. **Option A - Download from PortSwigger:**
   - Go to: https://portswigger.net/burp/extender/api/
   - Download `burp-extender-api.jar`
   - Save it in the project root folder

2. **Option B - Extract from Burp:**
   - The API is already included in Burp Suite
   - We'll reference it during compilation (see below)

### Step 2: Compile the Extension

Navigate to the project directory and run:

```bash
# Create output directory
mkdir -p out

# Compile (if you downloaded burp-extender-api.jar)
javac -cp burp-extender-api.jar -d out src/burp/*.java

# OR compile by referencing Burp's JAR directly (replace path to your Burp JAR)
javac -cp "/path/to/burpsuite_community.jar" -d out src/burp/*.java
```

**Example for Linux/Mac:**
```bash
javac -cp "/home/user/burpsuite_community_v2024.jar" -d out src/burp/*.java
```

**Example for Windows:**
```bash
javac -cp "C:\Program Files\BurpSuiteCommunity\burpsuite_community.jar" -d out src\burp\*.java
```

### Step 3: Create JAR File

```bash
# Navigate to output directory
cd out

# Create JAR file
jar -cf LinkExtractor.jar burp/*.class

# Move back to project root
cd ..
```

Your compiled extension is now at: `out/LinkExtractor.jar`

### Step 4: Load Extension in Burp Suite

1. **Open Burp Suite Community Edition**

2. **Go to Extensions tab:**
   - Click on **"Extensions"** tab (top menu)
   - Go to **"Installed"** sub-tab

3. **Add the extension:**
   - Click **"Add"** button
   - **Extension type:** Select "Java"
   - **Extension file:** Click "Select file" and choose `out/LinkExtractor.jar`
   - Click **"Next"**

4. **Verify installation:**
   - You should see "Link Extractor loaded successfully!" in the output
   - A new tab called **"Link Extractor"** should appear in Burp

---

## Usage

### Basic Usage

1. **Start browsing** through Burp's proxy (default: http://127.0.0.1:8080)

2. **Links will appear automatically** in the "Link Extractor" tab as you browse

3. **View results** organized by source URL:
   ```
   ┌─ SOURCE URL:
   │  https://example.com/page
   │
   └─ DISCOVERED LINKS (5):
      • https://example.com/api/users
      • https://example.com/login
      • https://api.example.com/v1/data
      ...
   ```

### Scope Filter

- **Enable scope filter:** Check the "Only show in-scope URLs" checkbox
- This will only capture links from URLs defined in your target scope
- To set scope: Go to "Target" → "Scope" tab in Burp

### Export Links

1. Click the **"Export to File"** button
2. Choose a location and filename (default: `extracted_links.txt`)
3. All discovered links will be saved in a formatted text file

### Clear Links

- Click **"Clear All"** button to remove all extracted links and start fresh

---

## What Gets Extracted?

### 1. Absolute URLs
```
http://example.com/page
https://api.example.com/v1/users
```

### 2. Relative Paths (converted to absolute)
```
Source: https://target.com/page

Found in response: "/api/login"
Result: https://target.com/api/login
```

### 3. Method-Endpoint Patterns
```
Method="GET" "/users/profile"
→ Extracted as: https://target.com/users/profile
```

### 4. Relative References
```
"../api/data"
"./images/logo.png"
```

---

## Build Script (Optional)

For easier compilation, you can use the provided build script:

### Linux/Mac:
```bash
chmod +x build.sh
./build.sh
```

### Windows:
```bash
build.bat
```

---

## Troubleshooting

### "Cannot find symbol" error during compilation
- Make sure you have the Burp API JAR file referenced correctly
- Verify the path to `burpsuite_community.jar` or `burp-extender-api.jar`

### Extension doesn't load in Burp
- Check the "Errors" tab in Extensions
- Make sure you compiled with a compatible Java version (JDK 8+)
- Verify the JAR file was created correctly: `jar -tf out/LinkExtractor.jar`

### No links appearing
- Make sure you're sending HTTP traffic through Burp's proxy
- Check if scope filter is enabled (disable it to capture all traffic)
- Verify the extension is loaded: Check "Extensions" → "Installed"

### Java version mismatch
- Burp Community uses Java 21 internally, but JDK 8+ should work for extensions
- Compile with the same or lower Java version than your Burp installation

---

## Development

### Project Structure
```
burp-extensions/
├── src/
│   └── burp/
│       ├── BurpExtender.java        # Main extension class
│       └── LinkExtractorPanel.java  # UI components
├── out/
│   └── LinkExtractor.jar            # Compiled extension
├── README.md                         # This file
└── build.sh / build.bat             # Build scripts
```

### How It Works

1. **HTTP Listener** - Intercepts all HTTP responses
2. **Link Extraction** - Uses regex patterns to find URLs and endpoints
3. **URL Resolution** - Converts relative paths to absolute URLs
4. **Deduplication** - Maintains a global set of unique links
5. **UI Update** - Displays results in real-time

---

## Credits

Inspired by **LinkFinder** tool for JavaScript endpoint discovery.

---

## License

This extension is provided as-is for educational and authorized security testing purposes.

---

## Support

If you encounter issues:
1. Check the Burp "Extensions" → "Errors" tab
2. Review the compilation steps above
3. Verify your Java installation: `java -version`

Happy bug hunting! 🔍
