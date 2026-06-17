#!/bin/bash
# FileVault — start the local server and open in a supported browser.
#
# IMPORTANT: FileVault relies on the File System Access API, which Safari and
# Firefox do NOT support. Safari also force-upgrades localhost to HTTPS, which
# is why it refused to load over http://. So we deliberately open the app in
# Chrome / Brave / Edge — NOT the system default browser.

PROJECT="/Volumes/PRO-G-HomeX/Claude/Projects/HTML 001"
URL="http://localhost:8765/FileVault.html"

# Start the server if it isn't already running
if lsof -i :8765 -t > /dev/null 2>&1; then
    echo "Server already running on port 8765."
else
    echo "Starting FileVault server on http://localhost:8765..."
    /opt/homebrew/bin/python3 "$PROJECT/server.py" &
    sleep 1
fi

# Find a supported (Chromium-based) browser, in order of preference.
BROWSER=""
for app in "Google Chrome" "Brave Browser" "Microsoft Edge"; do
    if [ -d "/Applications/$app.app" ]; then
        BROWSER="$app"
        break
    fi
done

echo ""
if [ -n "$BROWSER" ]; then
    echo "Opening FileVault in $BROWSER..."
    open -a "$BROWSER" "$URL"
else
    echo "No Chrome/Brave/Edge found. Opening in your default browser,"
    echo "but if it is Safari the file picker will NOT work."
    open "$URL"
fi

echo ""
echo "FileVault is running at $URL"
echo "Supported browsers: Chrome, Brave, Edge (NOT Safari or Firefox)."
echo "Close this window when you're done (the server keeps running in the background)."
