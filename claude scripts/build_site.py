"""Build the password-protected travel site.

Reads the plaintext pages from src/, encrypts each one with AES-256-GCM using a
key derived from TRAVEL_PASSWORD (.env), and writes the result to docs/ as a
self-contained "unlock" page. Only docs/ gets published to GitHub Pages, so the
readable text never leaves this machine.

Usage
    uv run "claude scripts/build_site.py"              build src/ -> docs/
    uv run "claude scripts/build_site.py" --decrypt    recover docs/ -> src/

Crypto
    key   = PBKDF2-HMAC-SHA256(password, salt, 300_000 iterations, 32 bytes)
    blob  = salt(16) || iv(12) || AES-256-GCM(ciphertext || tag)
    The browser reverses this with the WebCrypto API; the key is never stored.

Assumptions
    - GitHub Pages serves static files only, so there is no server that could
      check a password. Encrypting the pages is the only way to keep them
      unreadable in a public repo.
    - One shared password, no usernames, exactly as requested.
    - src/ is gitignored. The published ciphertext is the backup: --decrypt
      restores the originals as long as the password is known.
    - Anyone with the password can share the decrypted page. This protects
      against strangers finding the URL, not against the five people invited.
    - Every .html file in src/ is a full standalone page; scripts inside it
      (Leaflet, the carousels) run after decryption via document.write.
    - The build is deterministic, so git only records pages that really changed.
      The cost is that comparing two commits shows which pages were touched.
      That is fine here: git reveals that anyway, and the content stays sealed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import secrets
import shutil
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
OUT = ROOT / "docs"
ENV = ROOT / ".env"

ITERATIONS = 300_000
SALT_BYTES = 16
IV_BYTES = 12
ENV_KEY = "TRAVEL_PASSWORD"


# --------------------------------------------------------------------------- env


def read_env(path: Path) -> dict[str, str]:
    """Minimal .env parser: KEY=value per line, # starts a comment."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def get_password() -> str:
    """Password from .env, or from the environment, generating .env if missing."""
    password = read_env(ENV).get(ENV_KEY) or os.environ.get(ENV_KEY, "")
    if password:
        return password

    password = secrets.token_urlsafe(9)  # ~72 bits of entropy
    ENV.write_text(
        "# Shared password for the travel pages. Not committed to git.\n"
        "# Change it, then rebuild to re-encrypt every page.\n"
        f"{ENV_KEY}={password}\n",
        encoding="utf-8",
    )
    ENV.chmod(0o600)
    print(f"No .env found, so one was created with a generated password:\n\n    {password}\n")
    return password


# ------------------------------------------------------------------------ crypto


def encrypt(plaintext: str, password: str) -> str:
    # Salt and iv are derived from the password and the page itself instead of
    # being random, so rebuilding unchanged input produces byte-identical output.
    # Without this every commit would rewrite every page in full. An iv is only
    # ever reused for the exact same plaintext under the same password, which is
    # the one case where reuse is harmless.
    material = password.encode() + b"\x00" + plaintext.encode("utf-8")
    salt = hashlib.sha256(b"travel/salt" + material).digest()[:SALT_BYTES]
    iv = hashlib.sha256(b"travel/iv" + material).digest()[:IV_BYTES]
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS, 32)
    body = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    return base64.b64encode(salt + iv + body).decode("ascii")


def decrypt(blob_b64: str, password: str) -> str:
    blob = base64.b64decode(blob_b64)
    salt, iv, body = blob[:SALT_BYTES], blob[SALT_BYTES : SALT_BYTES + IV_BYTES], blob[SALT_BYTES + IV_BYTES :]
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS, 32)
    return AESGCM(key).decrypt(iv, body, None).decode("utf-8")


# -------------------------------------------------------------------- gate page

GATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Travel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bodoni+Moda:opsz,wght@6..96,400&family=Archivo:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --marmo:#EFEDEA; --marmo-2:#E4E1DC; --nebbia:#CFCAC4;
  --inchiostro:#22272A; --ombra:#6B6660; --verderame:#46685C; --candoglia:#B49B99;
  --display:"Bodoni Moda","Bodoni 72","Didot","Hoefler Text",Georgia,serif;
  --body:"Archivo","Helvetica Neue",Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;display:grid;place-items:center;
  background:var(--marmo);color:var(--inchiostro);
  font-family:var(--body);font-size:16px;line-height:1.62;
  -webkit-font-smoothing:antialiased;padding:1.5rem;
}
.gate{width:100%;max-width:330px;text-align:center}
h1{
  font-family:var(--display);font-weight:400;letter-spacing:-.01em;
  font-size:clamp(3rem,11vw,4.2rem);line-height:.9;margin:0;
}
.rule{height:1px;background:var(--nebbia);margin:1.5rem 0}
.eyebrow{
  font-size:.68rem;font-weight:600;letter-spacing:.18em;text-transform:uppercase;
  color:var(--ombra);margin:0 0 1.6rem;
}
form{display:flex;flex-direction:column;gap:.7rem}
input{
  font-family:var(--body);font-size:1rem;color:var(--inchiostro);
  background:transparent;border:1px solid var(--nebbia);border-radius:0;
  padding:.8rem .9rem;width:100%;text-align:center;letter-spacing:.04em;
}
input:focus{outline:2px solid var(--verderame);outline-offset:-1px}
button{
  font-family:var(--body);font-size:.72rem;font-weight:600;
  letter-spacing:.16em;text-transform:uppercase;cursor:pointer;
  background:var(--inchiostro);color:var(--marmo);
  border:1px solid var(--inchiostro);border-radius:0;padding:.85rem 1rem;
  transition:background .2s ease,color .2s ease;
}
button:hover{background:transparent;color:var(--inchiostro)}
button:disabled{opacity:.5;cursor:wait}
.msg{
  min-height:1.4em;margin:1rem 0 0;font-size:.78rem;
  letter-spacing:.09em;text-transform:uppercase;color:var(--ombra);
}
.msg.bad{color:var(--candoglia)}
noscript{display:block;margin-top:1rem;font-size:.85rem;color:var(--ombra)}
</style>
</head>
<body>

<main class="gate">
  <h1>Travel</h1>
  <div class="rule"></div>
  <p class="eyebrow">Password required</p>

  <form id="f" autocomplete="on">
    <input id="pw" type="password" name="password" placeholder="Password"
           aria-label="Password" autocomplete="current-password" autofocus required>
    <button id="go" type="submit">Unlock</button>
  </form>

  <p class="msg" id="msg" role="status" aria-live="polite"></p>
  <noscript>This page needs JavaScript to decrypt.</noscript>
</main>

<script id="payload" type="application/octet-stream">__PAYLOAD__</script>
<script>
(function(){
  var ITER = __ITERATIONS__, SALT = __SALT_BYTES__, IV = __IV_BYTES__, STORE = "travel:pw";
  var form = document.getElementById("f"),
      input = document.getElementById("pw"),
      button = document.getElementById("go"),
      msg = document.getElementById("msg");

  var blob = Uint8Array.from(
    atob(document.getElementById("payload").textContent.trim()),
    function(c){ return c.charCodeAt(0); }
  );

  function say(text, bad){
    msg.textContent = text;
    msg.classList.toggle("bad", !!bad);
  }

  async function unlock(password){
    var enc = new TextEncoder();
    var base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    var key = await crypto.subtle.deriveKey(
      { name:"PBKDF2", salt: blob.slice(0, SALT), iterations: ITER, hash:"SHA-256" },
      base, { name:"AES-GCM", length:256 }, false, ["decrypt"]
    );
    var plain = await crypto.subtle.decrypt(
      { name:"AES-GCM", iv: blob.slice(SALT, SALT + IV) }, key, blob.slice(SALT + IV)
    );
    return new TextDecoder().decode(plain);
  }

  function render(html){
    document.open();
    document.write(html);
    document.close();
  }

  async function attempt(password, silent){
    if (!password) return false;
    button.disabled = true;
    if (!silent) say("Decrypting");
    try {
      var html = await unlock(password);
      try { sessionStorage.setItem(STORE, password); } catch (e) {}
      render(html);
      return true;
    } catch (e) {
      try { sessionStorage.removeItem(STORE); } catch (e2) {}
      if (!silent) say("Wrong password", true);
      button.disabled = false;
      return false;
    }
  }

  form.addEventListener("submit", function(e){
    e.preventDefault();
    attempt(input.value, false);
  });

  if (!window.crypto || !crypto.subtle){
    say("This browser cannot decrypt. Open the page over https.", true);
    button.disabled = true;
    return;
  }

  // Already unlocked earlier this session: go straight through.
  var saved = null;
  try { saved = sessionStorage.getItem(STORE); } catch (e) {}
  if (saved) attempt(saved, true);
})();
</script>

</body>
</html>
"""


# ------------------------------------------------------------------------- build


def build(password: str) -> list[Path]:
    pages = sorted(p for p in SRC.rglob("*.html") if p.is_file())
    if not pages:
        sys.exit(f"No .html files found in {SRC}")

    written: list[Path] = []
    for page in pages:
        target = OUT / page.relative_to(SRC)
        target.parent.mkdir(parents=True, exist_ok=True)
        gate = (
            GATE.replace("__PAYLOAD__", encrypt(page.read_text(encoding="utf-8"), password))
            .replace("__ITERATIONS__", str(ITERATIONS))
            .replace("__SALT_BYTES__", str(SALT_BYTES))
            .replace("__IV_BYTES__", str(IV_BYTES))
        )
        target.write_text(gate, encoding="utf-8")
        written.append(target)
        print(f"  {page.relative_to(ROOT)} -> {target.relative_to(ROOT)}  ({len(gate) / 1024:.0f} kB)")

    (OUT / ".nojekyll").touch()

    # Sanity check: every page must decrypt back to exactly what went in.
    for page, target in zip(pages, written):
        blob = target.read_text(encoding="utf-8").split('type="application/octet-stream">')[1].split("</script>")[0]
        if decrypt(blob.strip(), password) != page.read_text(encoding="utf-8"):
            sys.exit(f"Round-trip check failed for {target}")
    return written


def recover(password: str) -> None:
    """Rebuild the plaintext sources from the published ciphertext."""
    pages = sorted(p for p in OUT.rglob("*.html") if p.is_file())
    for page in pages:
        blob = page.read_text(encoding="utf-8").split('type="application/octet-stream">')[1].split("</script>")[0]
        target = SRC / page.relative_to(OUT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(decrypt(blob.strip(), password), encoding="utf-8")
        print(f"  {page.relative_to(ROOT)} -> {target.relative_to(ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--decrypt", action="store_true", help="recover docs/ back into src/")
    parser.add_argument("--clean", action="store_true", help="empty docs/ before building")
    args = parser.parse_args()

    password = get_password()

    if args.decrypt:
        print(f"Decrypting {OUT.name}/ into {SRC.name}/")
        recover(password)
        return

    if args.clean and OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True, exist_ok=True)

    print(f"Encrypting {SRC.name}/ into {OUT.name}/")
    written = build(password)
    print(f"\n{len(written)} page(s) built and verified. Publish the {OUT.name}/ folder.")


if __name__ == "__main__":
    main()
