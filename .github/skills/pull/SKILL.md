---
name: pull
description: "Fetch all public source repos from github.com/parsiya, filter out forks and non-code repos, and create update.md. Use when: updating repo catalog, fetching new repos, generating update.md, /pull."
argument-hint: "Optional: --dry-run to only list new repos"
---

# Get Repository Info
Fetch all public, non-fork (source) repositories from a GitHub account and
create `update.md` in the repository root with categorized entries when new
repos exist.

## When to Use

* Cataloging new repos that need to be added to this repository
* Regenerating the update.md file with fresh data from GitHub

## Script Reference
See [scripts/README.md](./scripts/README.md) for script details and outputs.

## Procedure

1. `Run the fetch script`:
  * Run from the workspace root:
    ```sh
    python .github/skills/pull/scripts/fetch_repos.py
    ```
  * Use `--dry-run` to list new repos without fetching or writing files.
  * Review the script output for the summary.
  * If the script fails, reports 0 new repos, or every repo has `ERROR:`
    markers, stop and ask before continuing.
2. `Classify and categorize each repo in update.md`:
  * For each repo, inspect the `README:` field first.
  * If `README:` points to a file path, read that README and check the 
    metadata (Language, Topics, Homepage).
  * If `README:` is `ERROR:`, classify using metadata only. If the category is
    unclear, stop and ask before continuing.
  * `If it is NOT a code repo` (e.g., website/blog, GitHub Pages, Hugo
    content-only site, profile README, slides without code):
    * Add the repo name to [exclude-repos.md](./references/exclude-repos.md) on its own line.
    * Remove it from update.md.
  * `If it IS a code repo`, assign a category:
    * Check existing categories in README.md (`##` section headings).
    * Use an existing category if it fits, otherwise create a new one.
  * Pay attention to repos with `ERROR:` markers — they may need manual review.
3. `Rewrite update.md` with categorized entries:
   ```markdown
   # Category Name

   ## repo-name
   https://github.com/parsiya/repo-name

   Description from GitHub.

   blog link: URL (if found in repo README or Homepage field)
   blog title: Title (if found in repo README)
   ```
  * Group repos by category (`#` heading) with each repo as `##`.
  * If you are creating a new category, clearly mention it.
  * Include the GitHub URL, description, and any blog links found in the
    repo's README or Homepage field.
  * Remove the metadata fields (Language, Topics, README path) — those were
    just for classification.
4. `Report summary`: Tell the user how many repos were found, how many were
  filtered out, and how many are in update.md.
