#!/bin/bash

echo "========================================="
echo "  Burp Link Extractor - Build Script"
echo "========================================="
echo ""

# Create output directory
echo "[1/3] Creating output directory..."
mkdir -p out

# Check if burp-extender-api.jar exists
if [ -f "burp-extender-api.jar" ]; then
    echo "[2/3] Compiling using burp-extender-api.jar..."
    javac -cp burp-extender-api.jar -d out src/burp/*.java

    if [ $? -ne 0 ]; then
        echo "ERROR: Compilation failed!"
        exit 1
    fi
else
    echo "WARNING: burp-extender-api.jar not found!"
    echo ""
    echo "Please either:"
    echo "  1. Download burp-extender-api.jar from https://portswigger.net/burp/extender/api/"
    echo "  2. Or compile manually using your Burp JAR file:"
    echo "     javac -cp /path/to/burpsuite_community.jar -d out src/burp/*.java"
    echo ""
    exit 1
fi

# Create JAR file
echo "[3/3] Creating JAR file..."
cd out
jar -cf LinkExtractor.jar burp/*.class
cd ..

if [ -f "out/LinkExtractor.jar" ]; then
    echo ""
    echo "========================================="
    echo "  Build Successful!"
    echo "========================================="
    echo ""
    echo "Extension JAR created at: out/LinkExtractor.jar"
    echo ""
    echo "Next steps:"
    echo "  1. Open Burp Suite Community Edition"
    echo "  2. Go to Extensions -> Installed"
    echo "  3. Click 'Add' and select 'out/LinkExtractor.jar'"
    echo ""
else
    echo ""
    echo "ERROR: Failed to create JAR file!"
    exit 1
fi
