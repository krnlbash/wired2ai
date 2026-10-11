# Browser upload and release workflow

**Maintainer preference: all wired2ai files and releases are uploaded through
GitHub's website.** This applies to the first release and future versions.
Terminal commands in other documentation are for developing, installing or
testing on Linux; publishing does not require Git Bash, a GitHub connector or
command-line Git.

## Upload the complete project from Windows

1. Download the latest `wired2ai-0.1.0a1-github-browser.zip` and choose **Extract All**
   in Windows. Extract into a new folder so files from an older package cannot
   be mixed into the upload.
2. Open that folder. It should contain `README.md` and `pyproject.toml` directly,
   alongside `.github`, `docs`, `examples`, `schemas`, `src`, and `tests`.
   The ZIP contains 34 files, and every file belongs in the repository.
3. Open the `krnlbash/wired2ai` repository in the browser. Choose **Add file →
   Upload files**, or the existing-file upload link if GitHub shows an empty
   repository setup page.
4. In Windows File Explorer, select all the contents of the extracted folder
   and drag them onto the upload page. Drag the contents, not the enclosing
   extraction folder or the ZIP itself. Keep the directory structure intact.
5. Check that the upload includes `pyproject.toml`, `.gitignore`,
   `.github/workflows/ci.yml`, and `docs/VALIDATION.md`. The latter must not be
   nested under `examples/`. Include both `src/wired2ai/__init__.py` and
   `src/wired2ai/__main__.py`.
6. Enter a commit message such as `Upload complete wired2ai 0.1.0a1 source` and
   commit the files to `main`. If your repository requires a pull request,
   follow that branch/review flow in the browser.
7. Confirm that the main repository page displays the README and that
   `pyproject.toml`, `src`, and `docs` are at the top level. Open **Actions** to
   check the test run. Report a failure with the job's actual error output.

This source archive contains no virtual environment, build directory, wheel,
Git bundle or local Git metadata. It needs no file exclusions before upload.
All ZIP entries have Windows hidden/system attributes cleared. A viewer may
still hide dot-prefixed names; extraction preserves `.github` and `.gitignore`.

## If a dot-prefixed path is missing from the upload

Use Windows File Explorer's view options to show hidden items if necessary.
If a path still cannot be selected, commit the other files and use GitHub's
**Add file → Create new file** page. For the workflow, type the full path
`.github/workflows/ci.yml`, paste the contents of that file from the extracted
archive, and commit. GitHub creates the directories from the slashes. For
`.gitignore`, use that exact filename at the repository root.

Uploading a ZIP as one repository file does not unpack the archive. The Python
files must exist in their actual folders.

## Create the alpha release through the browser

After the upload and review, use the repository's **Releases** page to draft a
release. Create or select the tag `v0.1.0-alpha.1` against the intended `main`
commit. Use `wired2ai 0.1.0 alpha 1` as the title and summarize the actual
capabilities, local validation and remaining Kali validation. Mark it as a
**pre-release**. Attach the source ZIP as an asset if useful, then publish when
the details are ready. GitHub also supplies source archives for tagged releases.

The browser upload creates its own GitHub commits. Local development commits
and tags are not imported by uploading files. A release tag must be created
on GitHub separately; keep published tags fixed once users depend on them.

## Future versions

Upload updated files to their existing paths in the same repository, then make
a new browser commit with a meaningful description. Preserve the existing
repository/history. Remove a file through GitHub only when that release
explicitly retires it; uploading a replacement ZIP's contents does not delete
obsolete repository files automatically.

Before each release, update the application version, changelog and examples as
appropriate, run meaningful tests, and record the real environment/results in
`docs/VALIDATION.md`. Publish the next tag/pre-release through the same browser
workflow. Documentation-only packaging changes can retain the application
version when the runtime code is unchanged.

For this alpha, the local suite passed 59 tests on Ubuntu 24.04/Python 3.12.
That record does not establish a passing hosted workflow or Kali validation.
The prepared CI workflow runs on Ubuntu 24.04. Check its actual result after
uploading and validate separately in the Kali VM.

## GitHub references

- [Upload files through the website](https://docs.github.com/en/repositories/working-with-files/managing-files/adding-a-file-to-a-repository)
- [Create a file and nested directories](https://docs.github.com/en/repositories/working-with-files/managing-files/creating-new-files)
- [Manage releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
