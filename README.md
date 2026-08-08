# Travel

Static index page linking to the trip guides, published behind a single shared
password. No build server, no accounts: just encrypted HTML.

```
src/                     plaintext pages — never committed
  index.html             overview page listing every trip
  trips/milan.html       Milan, 8 – 10 August 2026
docs/                    what gets published — encrypted, unreadable without the password
.env                     TRAVEL_PASSWORD — never committed
claude scripts/build_site.py
```

## How the password works

GitHub Pages only serves files; there is no server that can check a password, and
anything in a published file can be read with "view source". So the pages are
encrypted before they are published:

- `build_site.py` derives a key from `TRAVEL_PASSWORD` with PBKDF2-SHA256
  (300 000 iterations) and encrypts each page with AES-256-GCM.
- `docs/` holds only the ciphertext plus a small unlock form.
- The browser decrypts in memory after you type the password. It is remembered
  for the browser session, so the trip pages don't ask again.
- A wrong password fails on the authentication tag; there is nothing to guess
  past.

The password is only as strong as you make it. A guessable one can be cracked
offline, because anyone can download the ciphertext.

## Editing and publishing

Edit the pages in `src/`, then commit and push:

```bash
git add -A && git commit -m "Update trips" && git push
```

Because `src/` is gitignored, a change to a trip page leaves git's index empty
and `git commit` aborts before it notices the rebuild. So after editing `src/`,
publish in one step:

```bash
"claude scripts/publish" "Add the Lisbon trip"
```

That builds, commits and pushes. A pre-commit hook does the same rebuild
whenever you commit by hand, so the published site can never lag behind `src/`,
and it refuses to commit `src/` or `.env`. To build without committing:

```bash
uv run "claude scripts/build_site.py"
```

After a fresh clone the hook has to be linked once (git does not clone hooks):

```bash
ln -sf "../../claude scripts/pre-commit" .git/hooks/pre-commit
```

The build is deterministic: rebuilding an unchanged page produces byte-identical
output, so git only records the pages you actually edited.

Preview locally before pushing:

```bash
python3 -m http.server 8000 --directory docs
# open http://localhost:8000
```

To change the password, edit `.env` and rebuild — every page is re-encrypted.

## Adding a trip

1. Put the new file in `src/trips/`, e.g. `src/trips/lisbon.html`.
2. Open `src/index.html` and find the comment block at the bottom of the
   `<ul class="trips">` list.
3. Copy the example block, remove the comment markers and update the `href`,
   number, name, dates and photo.
4. Rebuild.

For a trip whose page isn't ready yet there is a second example block with
`class="soon"`. That row shows a "Soon" label and isn't clickable.

## Backups

`src/` and `.env` stay on this machine only. Keep the password somewhere safe:
it is what makes `docs/` recoverable.

```bash
uv run "claude scripts/build_site.py" --decrypt   # rebuilds src/ from docs/
```

## Publishing with GitHub Pages

One-time setup, once the repo is on GitHub:

1. Go to **Settings → Pages** in the repo.
2. Under **Source**, pick **Deploy from a branch**.
3. Branch: `main`, folder: **`/docs`**. Save.

After a minute the site is live at `https://<username>.github.io/<repo-name>/`.
Every push to `main` republishes it.
