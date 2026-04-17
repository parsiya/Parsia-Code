---
name: push
description: "Read update.md and add each item to README.md under the correct section, run git submodule add, then verify. Use when: adding repos to README, running submodule adds, /push."
---

# Update README and Add Submodules
Read update.md from the workspace root and for each item:

* Add it to README.md under the correct category section.
* Run `git submodule add` for each repo.
* Verify everything was added.

## When to Use

* After running `/pull` to process the generated update.md
* When update.md has items that need to be added to README and cloned

## Procedure

### Step 1: Read update.md and README.md

* Read update.md from the workspace root.
* Parse each item: repo name, category, GitHub URL, description, blog links.
* If update.md does not exist or is empty, tell the user and stop.
* If anything unexpected happens (no items, malformed entries), stop and ask
  the user before proceeding.
* Read the full README.md and identify existing category sections (`##` headings).
* DO NOT TOUCH THE TABLE OF CONTENTS — it is auto-generated.

### Step 2: Add each item to README.md
For each item in update.md:

1. `Check if already in README`: Search README.md case-insensitively for an
  actual repo entry, not just the repo name.
  IMPORTANT: Actually read and search the file. Do NOT rely on memory.
  Treat the repo as present only if there is a `###` entry whose link target
  matches `(repo-name)` or `(repo-name/README.md)` case-insensitively.
  Do NOT count plain-text mentions, footnote/reference definitions, or GitHub
  URLs by themselves. If found, skip it and note it was already present.

2. `Find or create the category section`: Look for the matching `## Category`
   heading in README.md.
   * If the section exists, add the new entry at the end of that section
     (before the next `##` heading).
   * If the section doesn't exist, create a new `## Category` section.

3. `Format the entry` as a `###` subsection:
   ```markdown
   ### [repo-name](repo-name)
   Description.
   ```
   * If there are blog links, add reference-style links:
     ```markdown
     ### [repo-name](repo-name)
     Description. Blog: [Blog Title][repo-name-blog].
     ```
   * Add reference link definitions at the bottom of README.md:
     ```markdown
     [repo-name-blog]: https://parsiya.net/blog/...
     ```

### Step 3: Run git submodule add
For each item in update.md that was added to README (not skipped):

* Run `git submodule add <github-url> <repo-name>` from the workspace root.
* Wait for each command to complete before running the next.
* If a submodule already exists, note it and continue.

### Step 4: Verify (MANDATORY)

1. `Re-read README.md` from disk (not from memory).
2. `Re-read .gitmodules` from disk.
3. For EACH item in update.md:
   * In README.md, case-insensitively verify there is a `###` entry whose link
     target matches `(repo-name)` or `(repo-name/README.md)`. If NOT found:
     report as MISSING.
   * In `.gitmodules`, case-insensitively verify either `path = repo-name` or
     the exact GitHub URL exists. If NOT found: report as MISSING.
4. Fix any missing items before proceeding.

### Step 5: Report summary
Tell the user:

* Total items in update.md
* Items added to README.md
* Items skipped (already present)
* Items that failed verification
* New categories created (if any)
* Submodules added vs skipped

### Step 6: Clean up

* Remove items from update.md that are confirmed in README.md and `.gitmodules`.
* If all items are confirmed, tell the user update.md can be deleted.
* Do NOT delete update.md without user confirmation.
