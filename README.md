# DocVault

**A macOS CLI for verified, portable document encryption with two independent passwords.**

Turn a document folder into one encrypted `.7z` bundle, verify it before removing
plaintext, and restore it on another Mac using both passwords. Each bundle carries
its own protected recovery key, so recovery does not require the original machine's
local key.

- Two independent passwords, Argon2id derivation and hidden terminal input.
- Verification before publication and plaintext cleanup; `--keep` retains originals.
- Portable recovery, optional public password hints and supported Finder metadata.

![DocVault installation, encryption, verification and recovery demo](docs/media/demo.gif)

[Watch/download the MP4](docs/media/demo.mp4) · [Demo steps](docs/demo.md) ·
[Recovery format](docs/archive-recovery.md) · [Contributing](CONTRIBUTING.md)

**Status: alpha, macOS only.** Keep independent backups and test recovery on
sample documents first. See [security limitations](SECURITY.md).

## Quick start

Requires macOS, Python 3.12+, [Homebrew](https://brew.sh/), uv and modern 7-Zip
(21+; legacy p7zip is unsupported). Install prerequisites and clone:

```sh
brew install python@3.12 uv sevenzip
export PATH="$(brew --prefix python@3.12)/libexec/bin:$PATH"
git clone https://github.com/evgeny-trushin/DocVault.git
cd DocVault
```

For an installation without administrator access:

```sh
./install.sh --bin-dir "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
mkdir -m 700 "$HOME/docvault-key"
docvault init --key "$HOME/docvault-key/key"

# Start with a sample folder. --keep retains its plaintext files.
encrypt.sh "/path/to/Documents" --key "$HOME/docvault-key/key" --keep
docvault verify "/path/to/Documents.7z"

# Move retained originals aside, then restore from the bundle.
mv "/path/to/Documents" "/path/to/Documents.original"
decrypt.sh "/path/to/Documents.7z"
```

Choose a strong local key password during `init` and an independent outer password
during encryption. Press Enter to skip optional public hints; the example above
assumes no hints. Decryption and verification need both passwords and no local key.
Restoration refuses to overwrite existing files. Add the PATH line to your shell
configuration to use these commands in future terminals. Keep the checkout and
its `.venv` in place.

## Password protection

The local password is processed with **Argon2id and a random 16-byte salt**.
The default runs **3 passes using 256 MiB of memory**, producing a 32-byte derived
key that decrypts the stored random 7z password. The key file contains the salt,
derivation settings and encrypted archive password; neither your local password
nor its derived key is stored.

## System installation

After installing the prerequisites and cloning as above, run as your normal user:

```sh
./install.sh
```

The installer prepares the Python environment as your normal user, then requests
sudo to install root-owned `docvault`, `encrypt.sh` and `decrypt.sh` launchers into
`/usr/local/bin` and a small helper into `/usr/local/libexec/docvault`.
On first installation it asks you to choose the local password for your key.

**The default key is a real root-owned `/usr/local/bin/key` file, mode `600`, with
no ACL,** so no normal account can read, replace or re-permission it. Because whoever owns a
folder can rename files in it, the installer makes `/usr/local/bin` root-owned with
the sticky bit (keeping its group, e.g. `admin`, and that group's write access) and
prints the command to undo this. A user-owned Intel Homebrew in `/usr/local` must
then be run by an administrator. A valid existing key is re-protected in place with
unchanged contents; an invalid one stops installation and is left untouched. Run the
commands with `sudo`; the helper opens the encrypted key, then permanently switches
to the invoking user's UID, GID and supplementary groups before loading DocVault,
asking for the local password or running 7z. When a member of the macOS `admin`
group works on another regular user's documents, the helper switches to that
documents' owner instead, so staging and restored files keep the owner's
permissions. Archives belong to you, and restored files retain their recorded
permissions. No document operations run as root.

Keep this project directory and its `.venv` in place; the installed launcher runs
that environment after dropping privileges. Re-running `./install.sh` updates the
current launchers and helper while retaining the protected local key. Installation
refuses unrelated files, directories and symlinks.

`./uninstall.sh` removes the command launchers and retains your protected key,
helper, Python environment and archives.

## Use from any directory

```sh
cd "/path/to/Documents"
sudo encrypt.sh           # asks for hints; creates a .7z bundle; removes verified plaintext
sudo decrypt.sh           # finds the bundle, shows hints and restores beside it
```

Before creating a bundle, enter an optional hint group for each password:

```text
Envelope/key password hint (level 1): Hint1-Hint2-Hint-3
Outer 7z password hint (level 2): Hint4-Hint5-Hint6
```

The resulting filename is
`Documents__Hint1-Hint2-Hint-3__Hint4-Hint5-Hint6.7z`, using
`NAME__LEVEL-1__LEVEL-2.7z`. Each group is free text; hyphens can separate several
memory cues. Hints are **public**, so enter cues rather than passwords. Press Enter
to leave a group empty. Leaving both empty keeps the original `Documents.7z` name.
Hints cannot start with `_` or contain `__`, slashes, colons or control characters;
the full filename must fit within 255 UTF-8 bytes.

Decryption displays both labeled hints before asking for either password. Verification
and updates display them too. No-argument commands and folder shorthand discover
either naming format. If several matching bundles exist, use an explicit `.7z`
path for decryption/verification, or move extra bundles aside before encryption.
Updates retain the existing hints. Password changes also retain the filename;
rename its hint groups yourself if your password cues change. Filename hints are
not authenticated, and changing them does not change the passwords or restored
folder name.

Enter your existing **local 7z key password** first, then enter and confirm a new
**7z password** for creation. Decryption asks for the embedded-key password first,
then the 7z password. Both inputs are hidden. Incorrect passwords, confirmation
mismatches, and rejected new 7z passwords can be retried without a limit in the
terminal. Press **Ctrl-C** to cancel (Command-C if your terminal maps it to interrupt).
The two passwords must be independent: equal passwords and close variants are refused.
Passwords are stretched with Argon2id; brief status lines explain the pauses.

The current directory retains its inode. Decryption requires that it contain only
its bundle and refuses to overwrite documents. Encryption again updates the bundle
using its existing passwords and embedded secret, even without a local key.
Running encryption when only the bundle remains verifies and retains it.

Explicit paths work too:

```sh
sudo encrypt.sh "/path/to/Documents" --keep
# Omit --keep to remove plaintext after verification and durable publication.
docvault decrypt "/path/to/Documents"     # discover the sibling bundle, including hints
docvault verify "/path/to/Documents"
sudo encrypt.sh "/path/to/Documents"     # update the existing bundle
```

Copy, rename and back up only the resulting `.7z` bundle. It contains encrypted `encrypted.7z`
and `key` members; ordinary unpassworded 7z listings reveal neither member name.
Opening a bundle does not read, import or replace the receiving laptop's local key.
Bundle decryption and verification work without sudo. If invoked with sudo, the
installed launcher drops privileges before processing the bundle without opening
`/usr/local/bin/key`.

```sh
sudo docvault passwd                                # change only the machine-local key password
docvault bundle passwd "/path/to/Documents.7z" --layer outer
docvault bundle passwd "/path/to/Documents.7z" --layer key
```

Bundle password changes verify both layers and preserve inner ciphertext. Changing
the machine-local key password does not change existing bundles; they still need
their previous embedded-key password. Copied bundles retain their old passwords.
All archives made with one local key share its random secret: cracking a bundle's
two passwords exposes that secret and other bundles made with the same key. Use
separate local keys when bundles need independent archive secrets.

New bundle passwords need an estimated 10^18 guesses; 10^21 is recommended.
`--generate-password` samples six words from the vendored EFF large wordlist,
displays them once on the controlling terminal, and requires hidden typeback.
Strength reports go to stderr and show only guesses, attacker speed and time.
Estimates cannot establish the true strength of a human-chosen password.

Retain both bundle passwords independently of the laptops. The machine-local key
is needed only to create fresh bundles; existing bundles carry their own protected
copy of the archive secret.
Plain 7z cannot open a bundle with the typed outer password: DocVault first derives
a 64-character key with Argon2id. The [recovery format](docs/archive-recovery.md)
includes manual derivation instructions and its security limitations.

For a custom key or installation without administrator access:

```sh
./install.sh --bin-dir "$HOME/.local/bin"
mkdir -m 700 "$HOME/my-archive-key"
docvault init --key "$HOME/my-archive-key/key"
encrypt.sh "/path/to/Documents" --key "$HOME/my-archive-key/key"
decrypt.sh "/path/to/Documents.7z"
```

Without installation, use the launchers in `bin/`. Sudo requires the root-owned
launchers installed by the default installer. Re-run `./install.sh` after upgrading
to install the updated sudo helper.

For scripts, `--outer-password-fd FD` supplies the outer credential and
`--password-fd FD` supplies the local/embedded-key credential. Creation reads two
matching outer entries; decryption reads one. Shared descriptors read the local
password first, then the outer entries. Descriptor input fails on invalid passwords
or EOF instead of retrying. Password changes accept
`--new-outer-password-fd FD` or `--new-key-password-fd FD`, or the selected layer's
`--new-password-fd FD`, with two matching entries. Local `init` reads two entries;
local `passwd` also accepts `--new-password-fd FD`. Passwords never appear in
arguments, environment variables or password files created by DocVault.
`--allow-kdf-cost` approves embedded derivation costs above the sensitive profile;
otherwise the terminal requires `ACCEPT` before deriving the embedded key.

Supply public hints in scripts with `--key-hint 'Hint1-Hint2-Hint3'` and
`--outer-hint 'Hint4-Hint5-Hint6'` during fresh encryption. A hint omitted for a
password supplied through a descriptor defaults to empty; hints never consume
password input. Existing bundles retain their filename, so these options apply
only to new bundles.

Close documents before encryption. Both layers are fully verified before publication
and plaintext cleanup. Failed verification retains originals; failed durability
barriers stop cleanup and report uncertain publication if replacement occurred.
Preserve any reported `.docvault-7z-*` staging directory after a failure.

Authenticated metadata preserves supported Finder attributes, permissions and
precise timestamps. Before encryption, unsupported `com.apple.metadata:*` extended
attributes are removed from source files and folders, with a message for each
removal; this also applies with `--keep`. Supported attributes, including Finder
tags, download information and Time Machine exclusions, are preserved. Links,
ACLs, resource forks and other unsupported metadata are refused.
See [the inner 7z workflow](docs/7z.md) for details.

## Develop

```sh
uv venv -p 3.12 .venv
uv pip install -p .venv/bin/python -e '.[test]'
.venv/bin/python -m pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and demo generation.

## License

Original code and documentation: [MIT](LICENSE). The bundled EFF wordlist is
CC BY 4.0; see [third-party notices](THIRD_PARTY_NOTICES.md).
