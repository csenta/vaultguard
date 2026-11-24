# Sample Application Backend

import os
import requests

# LEAKED GITHUB TOKEN
GITHUB_API_TOKEN = "ghp_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jK5"

# LEAKED OPENAI API KEY
OPENAI_KEY = "sk-proj-9xK2mP8qL4wV7zB1nC5vR3tY6uI0oA2sD4fG6hJ8kL0"

def get_repos():
    headers = {"Authorization": f"Bearer {GITHUB_API_TOKEN}"}
    return requests.get("https://api.github.com/user/repos", headers=headers)
