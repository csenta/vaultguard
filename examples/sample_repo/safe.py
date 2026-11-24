# Clean application file with zero leaks

import os

# Safe environment variable retrieval
API_KEY = os.environ.get("API_KEY", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Documentation placeholder should be filtered out by entropy/heuristics
DOCS_PLACEHOLDER = "YOUR_API_KEY_HERE"
DUMMY_KEY = "AKIAEXAMPLEKEY12345"
