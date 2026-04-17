"""
Fetch new public source repos from github.com/parsiya that are not already
in the exclusion list or .gitmodules.

Usage: python3 .github/skills/pull/scripts/fetch_repos.py [--dry-run]

Flags:
  --dry-run  List new repos without fetching READMEs or writing files.

Outputs:
  - tmp/new-repos.json     Array of {name, url} for new repos
  - tmp/repo-info.json     Description/homepage/topics for each new repo
  - tmp/repos.json         Full API response for new repos
  - tmp/readmes/{name}.md  Downloaded README for each new repo (skips existing)
    - update.md              Skeleton for AI to categorize (only if new repos exist)
  - Updates exclude-repos.md with submodule names (deduplicated)
"""

import json
import os
import sys
import urllib.request
import urllib.error

USERNAME = "parsiya"
API = "https://api.github.com"
EXCLUDE_FILE = ".github/skills/pull/references/exclude-repos.md"
GITMODULES_FILE = ".gitmodules"
OUTPUT_FILE = "tmp/new-repos.json"
REPO_INFO_FILE = "tmp/repo-info.json"
FULL_RESPONSE_FILE = "tmp/repos.json"
READMES_DIR = "tmp/readmes"
UPDATE_FILE = "update.md"


def github_get(url):
    """GET a GitHub API URL and return parsed JSON."""
    with urllib.request.urlopen(urllib.request.Request(url)) as r:
        return json.loads(r.read().decode())


def load_or_create_excludes():
    """Load exclusion list, create file if it doesn't exist."""
    os.makedirs(os.path.dirname(EXCLUDE_FILE), exist_ok=True)
    if not os.path.exists(EXCLUDE_FILE):
        open(EXCLUDE_FILE, "w").close()
        return set()
    return {line.strip().lower() for line in open(EXCLUDE_FILE) if line.strip()}


def load_submodule_names():
    """Extract repo names from .gitmodules URL lines."""
    if not os.path.exists(GITMODULES_FILE):
        return set()
    names = set()
    for line in open(GITMODULES_FILE):
        line = line.strip()
        if line.startswith("url = "):
            names.add(line.split("/")[-1].removesuffix(".git").lower())
    return names


def add_to_excludes(names):
    """Add names to exclusion list, deduplicate, write back."""
    existing = load_or_create_excludes()
    all_names = existing | {n.lower() for n in names}
    with open(EXCLUDE_FILE, "w") as f:
        for name in sorted(all_names):
            f.write(f"{name}\n")
    return all_names


def fetch_source_repos():
    """Fetch all public non-fork repos, paginating."""
    repos, page = [], 1
    while True:
        print(f"Fetching page {page}...")
        batch = github_get(f"{API}/users/{USERNAME}/repos?per_page=100&page={page}")
        if not batch:
            break
        repos.extend(r for r in batch if not r.get("fork"))
        page += 1
    return repos


def fetch_readme(name, default_branch):
    """Fetch README.md via raw.githubusercontent.com (no API call)."""
    url = f"https://raw.githubusercontent.com/{USERNAME}/{name}/{default_branch}/README.md"
    try:
        with urllib.request.urlopen(url) as r:
            return r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return f"ERROR: Failed to fetch README.md ({e})"


def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    # 1. Load exclusion list.
    excludes = load_or_create_excludes()
    print(f"Exclusion list: {len(excludes)} repos.")

    # 2. Read .gitmodules, add submodule names to exclusion list.
    submodule_names = load_submodule_names()
    print(f"Submodules: {len(submodule_names)} repos.")
    excludes = add_to_excludes(submodule_names)
    print(f"Exclusion list after adding submodules: {len(excludes)} repos.")

    # 3. Fetch source repos from GitHub.
    all_repos = fetch_source_repos()
    print(f"Source repos on GitHub: {len(all_repos)}.")

    # 4. Remove repos already in exclusion list.
    new_repos = [r for r in all_repos if r["name"].lower() not in excludes]
    print(f"New repos: {len(new_repos)}.")

    # Dry run: just print names and exit.
    if "--dry-run" in sys.argv:
        print("\n--- Dry Run ---")
        for r in new_repos:
            print(f"  {r['name']} - {r.get('html_url')}")
        print(f"\nTotal: {len(all_repos)}, Excluded: {len(excludes)}, New: {len(new_repos)}")
        return

    # 5. Write tmp/new-repos.json.
    output = [{"name": r["name"], "url": r["html_url"]} for r in new_repos]
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    # 6. Save full API response (has topics, dates, size, etc.).
    with open(FULL_RESPONSE_FILE, "w") as f:
        json.dump(new_repos, f, indent=2)

    # 7. Save repo info (description, homepage, topics) — no extra API calls.
    repo_info = [
        {
            "name": r["name"],
            "url": r["html_url"],
            "description": r.get("description") or "",
            "homepage": r.get("homepage") or "",
            "language": r.get("language") or "",
            "topics": r.get("topics") or [],
        }
        for r in new_repos
    ]
    with open(REPO_INFO_FILE, "w") as f:
        json.dump(repo_info, f, indent=2)

    if not new_repos:
        print("\nNo new repos. Skipping README fetch and update.md generation.")
        print(f"\n--- Summary ---")
        print(f"Total: {len(all_repos)}, Excluded: {len(excludes)}, New: {len(new_repos)}")
        print(f"\nFiles: {OUTPUT_FILE}, {REPO_INFO_FILE}, {FULL_RESPONSE_FILE}")
        return

    # 8. Fetch READMEs for each new repo (skip if already downloaded).
    os.makedirs(READMES_DIR, exist_ok=True)
    errors = []
    for r in new_repos:
        name = r["name"]
        readme_path = os.path.join(READMES_DIR, f"{name}.md")
        if os.path.exists(readme_path) and os.path.getsize(readme_path) > 0:
            print(f"Skipping README for {name} (already exists).")
            # Check if the existing file is an error.
            with open(readme_path) as rf:
                if rf.read(6) == "ERROR:":
                    errors.append(name)
            continue
        print(f"Fetching README for {name}...")
        content = fetch_readme(name, r.get("default_branch", "main"))
        open(readme_path, "w").write(content)
        if content.startswith("ERROR:"):
            errors.append(name)

    # 9. Write update.md skeleton.
    with open(UPDATE_FILE, "w") as f:
        f.write("# Uncategorized\n\n")
        for info in repo_info:
            name = info["name"]
            f.write(f"## {name}\n")
            f.write(f"{info['url']}\n\n")
            if info["description"]:
                f.write(f"Description: {info['description']}\n")
            else:
                f.write("Description: ERROR: No description on GitHub.\n")
            if info["homepage"]:
                f.write(f"Homepage: {info['homepage']}\n")
            if info["language"]:
                f.write(f"Language: {info['language']}\n")
            if info["topics"]:
                f.write(f"Topics: {', '.join(info['topics'])}\n")
            if name in errors:
                f.write("README: ERROR: Failed to fetch.\n")
            else:
                f.write(f"README: tmp/readmes/{name}.md\n")
            f.write("\n")

    # Summary.
    print(f"\n--- Summary ---")
    print(f"Total: {len(all_repos)}, Excluded: {len(excludes)}, New: {len(new_repos)}")
    if errors:
        print(f"README errors: {', '.join(errors)}")
    print(f"\nFiles: {OUTPUT_FILE}, {REPO_INFO_FILE}, {FULL_RESPONSE_FILE}, {UPDATE_FILE}, {READMES_DIR}/")


if __name__ == "__main__":
    main()
