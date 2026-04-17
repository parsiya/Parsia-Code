# fetch_repos.py
Fetches all public source repos from github.com/parsiya, filters out excluded
and already-present repos, downloads READMEs, and creates an `update.md`
skeleton when new repos exist.

## Usage
Run from the workspace root:

```sh
python .github/skills/pull/scripts/fetch_repos.py
```

Use `--dry-run` to list new repos without fetching READMEs or writing files:

```sh
python .github/skills/pull/scripts/fetch_repos.py --dry-run
```

## Output

* `update.md` in the workspace root — skeleton with repo metadata and topics
	(only written when new repos exist)
* `tmp/new-repos.json` — array of `{name, url}` for new repos
* `tmp/repo-info.json` — description, homepage, language, and topics per repo
* `tmp/repos.json` — full API response for new repos
* `tmp/readmes/{repo-name}.md` — downloaded README for each new repo (skips existing)
* Updates `exclude-repos.md` with submodule names (deduplicated and sorted)
