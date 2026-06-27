#!/bin/bash
# FileVault — start the local server and open in a supported browser.
#
# IMPORTANT: FileVault relies on the File System Access API, which Safari and
# Firefox do NOT support. So we deliberately open the app in Chrome / Brave / Edge.

PROJECT="$(cd "$(dirname "$0")" && pwd)"
PORT_FILE="$HOME/.filevault_port"
URL=""

# If a port file exists, check whether that server is still running.
if [ -f "$PORT_FILE" ]; then
    CACHED_PORT=$(cat "$PORT_FILE")
    if lsof -i :"$CACHED_PORT" -t > /dev/null 2>&1; then
        echo "Server already running on port $CACHED_PORT."
        URL="http://localhost:$CACHED_PORT/FileVault.html"
    else
        rm -f "$PORT_FILE"
    fi
fi

# Start the server if we don't have a live one.
if [ -z "$URL" ]; then
    echo "Starting FileVault server..."
    /opt/homebrew/bin/python3 "$PROJECT/server.py" &

    # Wait for server.py to write its chosen port (up to 3 s).
    PORT=""
    for i in $(seq 1 15); do
        sleep 0.2
        if [ -f "$PORT_FILE" ]; then
            PORT=$(cat "$PORT_FILE")
            break
        fi
    done

    if [ -z "$PORT" ]; then
        echo "ERROR: Server did not start in time."
        exit 1
    fi

    URL="http://localhost:$PORT/FileVault.html"
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
