"""
Timeline Forge Web Interface

This module provides a simple web interface to the Timeline Forge
metadata manipulation utility.
"""

import os
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "timeline_forge_secret_key"

@app.route('/')
def index():
    """Home page - provides info about Timeline Forge."""
    return """
    <html>
    <head>
        <title>Timeline Forge</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; line-height: 1.6; }
            .container { max-width: 800px; margin: 0 auto; }
            h1 { color: #333; }
            pre { background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }
            .note { background: #ffffcc; padding: 10px; border-left: 4px solid #ffcc00; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Timeline Forge</h1>
            <p>Advanced Metadata Manipulation Utility</p>
            
            <div class="note">
                <p><strong>Note:</strong> Timeline Forge is primarily a command-line utility. 
                This is a simple web interface for demonstration purposes.</p>
            </div>
            
            <h2>Usage from Command Line</h2>
            <pre>
# Display help
python timeline_forge.py --help

# Inspect metadata for a file
python timeline_forge.py inspect /path/to/file

# Modify a timestamp
python timeline_forge.py modify /path/to/file --type MODIFIED --value "2023-01-15 08:30:00"

# Reset a timestamp to current time
python timeline_forge.py reset /path/to/file --type ACCESSED
            </pre>
            
            <h2>Current Environment</h2>
            <p>To explore Timeline Forge's capabilities, open a terminal in this Replit project
            and try the examples shown above.</p>
            
            <h2>Advanced Features</h2>
            <ul>
                <li>Modification of file timestamps (creation, access, modification)</li>
                <li>Manipulation of MFT records (NTFS)</li>
                <li>Access to USN Journal entries (NTFS)</li>
                <li>Extended attribute management (EXT4)</li>
                <li>File flags manipulation (EXT4)</li>
                <li>Journal entry inspection</li>
            </ul>
        </div>
    </body>
    </html>
    """

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)