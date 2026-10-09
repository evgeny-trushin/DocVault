# Encrypted outer archive with a password-protected embedded key

Status: implemented, version 1. Portable two-password bundles are the only public
archive format. See [7z.md](7z.md) for inner archive and filesystem details.
Re-run `./install.sh` after source updates to update installed launchers and helper.

## One file, one nesting step, two passwords

Create an outer 7z archive with encrypted contents and encrypted headers. It has
exactly two regular files at its root, without an enclosing directory:

```text
Documents.7z                  encrypted with a key derived from the outer password
  encrypted.7z                encrypted with the random archive secret
  key                         archive secret wrapped by the local key password
```

The outer password and local key password are independent credentials. Both are
required for normal bundle decryption. Prompts ask for the local password first;
cryptographic processing still opens the outer layer before the embedded key:

```text
outer password -> Argon2id -> outer 7z key -> open Documents.7z -> encrypted.7z + key
local key password -> unlock key -> archive secret -> decrypt encrypted.7z
```

The typed outer password never reaches 7z. DocVault stretches it with Argon2id and
gives 7z the derived key as 64 hexadecimal characters; see
[Outer password derivation](#outer-password-derivation).

The local key password protects the embedded envelope. It is not the macOS login
password, sudo password, or a third recovery password. The inner archive password
is a random secret managed by DocVault; never ask the user to enter it.

The two passwords must differ. DocVault never reuses one entered password for both
layers, and refuses to create, update or re-password a bundle when the two match or
one is a close variant of the other; see [Password rules](#password-rules). With a
shared password, cracking the outer layer would open the embedded key for free.

The `key` member contains no plaintext password or archive secret. `encrypted.7z`
contains the ordinary document tree and existing authenticated `.docvault-7z.json`
metadata. Unwrap exactly one bundle level; never recursively interpret the inner
archive as another recovery bundle.

Use the Copy method for outer members, with solid compression disabled and 7z
encryption enabled for contents and headers. The inner archive retains existing
solid compression and encryption. Avoid recompressing encrypted bytes.

Copy, rename and back up only `Documents.7z`; internal names remain fixed. There is
no external recovery file. Without the outer password, a normal 7z listing must
not reveal even the two member names.

## Exact decryption experience

From a directory containing its bundle:

```text
~/openSource/encrypt/docs$ sudo decrypt.sh
Local 7z key password:
Enter 7z password:
```

If sudo needs authentication, its operating-system prompt may appear first. The
two prompts above are DocVault's prompts in the required order. Hide entered input;
never echo, log or include passwords in command-line arguments.

1. Resolve the legacy or hinted bundle in the current directory and freeze its
   bytes in private staging. Refuse ambiguous automatic selection.
2. Display any public filename hints, labeled by password. Ask `Local 7z key password: `,
   then `Enter 7z password: `. Derive the outer 7z key, then open and validate the
   outer listing with it and materialize its two members in private staging.
3. Only after opening the outer archive and validating its layout and KDF costs,
   decrypt the embedded `key` using the entered local password.
4. Verify the recovered secret and complete inner archive, then restore documents
   beside `docs.7z` using the existing exclusive restoration path.
5. Retain `docs.7z`; remove successfully used staging files.

Each layer requires one Argon2id derivation, about two seconds at default
costs on the development Mac. Show a short status line so the pause is not taken for
a hang. A bundle whose embedded key needs costs above the `sensitive` profile also
asks for approval before deriving the embedded key; see
[Embedded key format and cryptography](#embedded-key-format-and-cryptography).

If the outer password fails, keep the local password and prompt for the outer
password again, using the same frozen input. If the embedded password fails,
prompt for that password again without reopening the outer layer. Interactive
password retries have no attempt limit. Ctrl-C cancels with exit code 130;
Command-C also works if the terminal maps it to interrupt. Failed inner verification
publishes no documents and stops the operation. Descriptor input stops on invalid
passwords or EOF instead of retrying.

The same order applies to explicit paths and verification:

```sh
sudo decrypt.sh /path/to/Documents.7z
sudo docvault verify /path/to/Documents.7z
```

Bundle decryption always unlocks the embedded `key`. Do not read `/usr/local/bin/key`
first, skip either prompt, require `--use-recovery`, or silently import or
replace the receiver's local key. Unprivileged invocation also works: portable
bundle decryption needs no administrator access.

## Encryption, transfer and local-key loss

The local key holds a random 32-byte secret protected by the local password.
DocVault supplies that secret to the inner 7z process as 64 hexadecimal characters.
For a new bundle, unlock that local key and wrap a copy of its secret into `key`
using the same entered local password, a fresh salt, nonce and envelope ID, and the
KDF costs set out in
[Embedded key format and cryptography](#embedded-key-format-and-cryptography). The
embedded envelope is a separate record, not a literal copy of the machine's key file.

```sh
sudo encrypt.sh /path/to/Documents
```

Prompt in this order:

```text
Envelope/key password hint (level 1):
Outer 7z password hint (level 2):
Local 7z key password:
Enter 7z password:
Confirm 7z password:
```

The first two entries are optional public hint groups, stored in the filename as
`Documents__KEY-HINT__7Z-HINT.7z`. Leave both empty for `Documents.7z`.
`--key-hint` and `--outer-hint` supply them directly; omitted hints for
descriptor-supplied passwords default to empty. The first password entry unlocks
the existing local key and needs no confirmation. The last two entries set and
confirm the new outer password. There is no separate recovery-password prompt.
Before taking the archive lock or writing archive data:

1. Print the duplication warning and request the local password. Retry an incorrect
   local password until it unlocks the key or the user cancels.
2. Print the local password's [strength report](#strength-report) at the embedded
   key's KDF costs. If it is below the floor, stop and ask the user to change it
   with `sudo docvault passwd` first; the archive secret remains unchanged.
3. Request and confirm the new outer password. Require matching entries, the
   [strength floor](#password-rules), and the [similarity rule](#password-rules).
   Re-evaluate both passwords with the other as known input, then print the
   whole-bundle line.
4. On an empty, weak, similar or mismatched new password, explain the problem and
   prompt for a new outer password again. Keep the successfully unlocked local key.
   There is no attempt limit; Ctrl-C cancels the operation.

Descriptor input (`--outer-password-fd`, `--password-fd`) applies the same checks
and prints the same reports, but exits on invalid input or EOF. When sharing a
single descriptor, supply the local password first, followed by the two outer
entries.

Example retry after a confirmation mismatch (inputs remain hidden):

```text
Local 7z key password:
Unlocking local key with Argon2id…
Local 7z key password, pessimistic estimate:
  ...
Enter 7z password:
Confirm 7z password:
warning: The passwords do not match; nothing was changed
Try again, or press Ctrl-C to cancel (Command-C if your terminal maps it to interrupt).
Enter 7z password:
Confirm 7z password:
7z password, pessimistic estimate:
  ...
Whole bundle: ...
```

Write one `.7z` bundle with the chosen hints in its name. With `--keep`, retain
plaintext; otherwise remove it only after verifying and durably publishing the
complete bundle. With no path, write it inside the current `Documents/` directory.
Every creation and update uses the same two-layer format. Updates discover either
naming format and retain the bundle's existing name and hints.

If `/usr/local/bin/key` disappears, recover with the bundle, its outer password and
its local key password. Both passwords are needed; the local password alone is
insufficient.

On another laptop, the first prompt requires the password that protects the
bundle's embedded key, even if the receiver's local key uses a different password.
Neither the sender's protected key file nor the receiver's macOS login password is
needed. Existing macOS metadata and durability requirements still apply.

Updating an existing bundle first asks for its embedded-key password, then its
current outer password. Recover the secret from that bundle and preserve those
credentials unless explicitly changing them. Re-apply the similarity rule; if the
two passwords match, refuse the update and point to `docvault bundle passwd`. This
supports imported bundles without the originating machine's key. New archives still
require a local key in version 1.

## Password rules

Every bundle password can be guessed offline without limit, so DocVault applies
these rules wherever it accepts one. It cannot measure the real strength of a
password a person chose. The [strength report](#strength-report) therefore credits
each password only with the cheapest known way to find it, and only a generated
passphrase has known strength.

- **Not empty.** Reject an empty password for either layer.
- **Strength floor.** Refuse a password whose pessimistic estimate is below 10^18
  guesses (about 290 years at default costs on the reference machine). Warn below
  the recommended 10^21 guesses (about 290 thousand years, roughly a 71-bit random
  password).
- **Similarity rule.** After NFKC normalization and case folding, refuse when the two
  layers' passwords are equal, one contains the other, or their edit distance is 4
  or less. The estimate also takes the other password and each of its words as known
  inputs, so shared words lower it; both passwords must still pass the floor.
- **Duplication warning.** Before asking for the local password, always print
  that it must differ from the outer password and why. The
  similarity refusal repeats the reason and gives the first password's expected time,
  which is all a shared password would protect.
- **Generated passphrases.** `--generate-password` replaces the two new-password
  entries with six words drawn with `secrets` from a vendored copy of the EFF large
  wordlist (7,776 words, CC BY 4.0, 77.5 bits). Show it once on `/dev/tty`, never
  on stdout, in logs or in arguments, then ask the user to type it back in place of
  the confirmation. Its report uses the exact value, 7,776^6 ÷ 2 ≈ 1.1 × 10^23
  guesses, and it still passes through the similarity rule.

| Command | New password checked | Compared with |
|---|---|---|
| `encrypt` | outer (floor); local key password (floor) | each other |
| Updating an existing bundle | none | current outer and key passwords |
| `bundle passwd --layer outer` | new outer (floor) | current embedded-key password |
| `bundle passwd --layer key` | new embedded-key (floor) | current outer password |
| `decrypt`, `verify` | none | none |

Each row that checks a new password prints its strength report. `docvault init` and
`docvault passwd` print the report for the local key password as information.
The floor applies only when that password is first embedded in a bundle.

### Strength report

Print the report on stderr, next to the prompts, right after a password is set or
first embedded. Never log it, store it, or pass it to a subprocess. Never describe
the password's structure, such as its word count, digit runs or which attack was
cheapest: the screen may be seen or recorded, and a structure hint shrinks the
search. Show only the calculation:

```text
guesses needed  ÷  attacker speed  =  expected time
```

**Guesses needed** is the lowest of three attacks, so the report never credits a
password with more strength than the cheapest known way to find it:

1. **Exhaustive search** over the character classes the password uses (26 lowercase,
   26 uppercase, 10 digits, 33 ASCII symbols including space, plus 100 if any
   character is non-ASCII): pool^length ÷ 2.
2. **Pattern search:** the pinned `zxcvbn` estimate on the first 100 characters, with
   the other layer's password and its words as known inputs. It covers dictionary
   words, names, breached passwords, keyboard walks, repeats, sequences, dates and
   substitutions. Unmatched runs of four or more characters cost the pool size per
   character instead of `zxcvbn`'s 10, because only exhaustive search finds them.
   Shorter runs keep `zxcvbn`'s cost, which models the digits and symbols people
   append.
3. **Word-list search**, when the password contains at least two listed words of
   three or more letters. Multiply the cost of each word (the smallest of 7,776 if it
   is in the EFF large list, its `zxcvbn` frequency rank, the other password's word
   count if shared with it, and 26^length), 10^length per digit run, 33 per distinct
   symbol after the first, and 128 per other character; then halve. Capitalization
   and the first separator are free, because the attacker is assumed to know the
   format. This covers passphrases, which `zxcvbn` overrates.

**Attacker speed** is the reference machine's aggregate peak memory bandwidth divided
by the bytes one Argon2id guess moves at the layer's costs: memlimit × (3 × opslimit
− 1). Each block is written once and read once as a reference; later passes also read
the block they overwrite. The June 2026 reference is El Capitan (44,544 AMD MI300A ×
5.3 TB/s ≈ 2.4 × 10^17 bytes/s). That gives 1.1 × 10^8 guesses per second at default
costs and 2.0 × 10^7 at `sensitive`. LineShine, No. 1 on that list, has no GPUs and
is slower at this work. Keep these constants in one dated table and review them with
each TOP500 list (June and November). The report names the machine and list, so
users can see how current it is.

**Expected time** is guesses ÷ speed, shown to two significant figures in seconds,
minutes, hours, days or years. Use thousand, million, billion and trillion years,
then powers of ten. The whole-bundle line adds the two layers' times.

Calibration examples for tests, at default costs with `zxcvbn` 4.5.0:

| Password | Guesses needed | Expected time |
|---|---|---|
| `Summer2026!Summer2026!` | 5.5 × 10^7 | 1 second |
| `correct horse battery staple` | 5.7 × 10^12 | 14 hours |
| `maple-orbit-tundra-velvet-clamp` | 4.7 × 10^16 | 13 years |
| `q8fz2kd9x7mw` | 2.4 × 10^18 | 680 years |
| `unwashed-gauze-uncured-spinal-reclining-stucco` | 5.4 × 10^22 | 15 million years |
| `kX9#mQ2$vL7p` | 2.7 × 10^23 | 78 million years |
| `Tr0ub4dor&4` with `Tr0ub4dor&3` as the other password | 1.1 × 10^13 | 1.2 days |

The implementation corrects two preliminary calibration rows: pinned `zxcvbn`
4.5.0 gives 55,220,001 guesses for the repeated seasonal password, and the adjusted
pattern search with the other password and its alphabetic words gives
11,077,696,000,000 for the related-password example. The lower estimates are
retained. Neither password passes the floor.

## Outer password derivation

```text
outer_salt  = first 16 bytes of SHA-256("DOCVAULT-7Z-OUTER-v1")
            = b6b29a97b01ff79e2534f7f13a6531c4
outer_key   = Argon2id(UTF-8 outer password, outer_salt,
                       opslimit = 3, memlimit = 256 MiB, output = 32 bytes)
7z password = lowercase hexadecimal of outer_key (64 characters)
```

libsodium's Argon2id, used through PyNaCl, accepts only 16-byte salts, so the
20-byte label is hashed down rather than used directly. Password bytes are the
UTF-8 encoding as entered, without normalization, matching the local key. Version 1
fixes these parameters. Nothing about them is stored, because the outer archive has
no unencrypted header to hold them; changing them requires a new bundle format
version. Feed the hexadecimal string to 7z through a protected pipe, as the
archive secret is fed. Keep `outer_key` only for the operation; never store it or
the outer password in `key`, the machine-local key or document metadata.

Test vector: the password `correct horse battery staple` gives
`46ff9c2c74b641aaac53b10c2e468c25abcdfd901d398548b9c7621cd260e4da`.

Rationale: 7-Zip's own derivation runs SHA-256 2^19 times with no salt and little
memory. Per guess it is about 50 times cheaper than default Argon2id at the rates in
[Offline guessing cost](#offline-guessing-cost), it suits GPUs, and precomputed
tables for common passwords work against every 7z file. Stretching first makes an
outer guess cost the same as an embedded-key guess and makes generic 7z tables
useless. 7-Zip's derivation still runs on the 64-character result, at negligible
extra cost.

Trade-offs:

- The salt is fixed, not per bundle, because no unencrypted place exists to store
  one. The same outer password gives the same 7z key in every bundle and for every
  user. An attacker can build DocVault-specific tables, or test each guess against
  many bundles for one derivation. The embedded key's random salt has neither
  weakness. The strength floor is the defense.
- Plain 7-Zip cannot open the outer archive with the typed password. This costs
  nothing for recovery, because `key` still needs DocVault. For emergency manual
  extraction, any Argon2id implementation that accepts a 16-byte binary salt
  reproduces the 7z password. This prints it to the terminal:

```sh
python3 -c 'import getpass, hashlib, nacl.pwhash.argon2id as a
salt = hashlib.sha256(b"DOCVAULT-7Z-OUTER-v1").digest()[:16]
print(a.kdf(32, getpass.getpass().encode(), salt, opslimit=3, memlimit=256 << 20).hex())'
```

## Embedded key format and cryptography

Use strict JSON with exactly one envelope and this distinct schema:

```text
format: docvault-7z-recovery
version: 1
archive_sha256: SHA-256 of the complete encrypted.7z member
archive_bytes: exact size of that member
envelope_id: random 16-byte identifier encoded as hexadecimal
kdf: { alg, opslimit, memlimit, salt }
nonce: fresh XChaCha20-Poly1305 nonce
wrapped_secret: encrypted 32-byte archive secret plus authentication tag
```

Do not accept this schema as a machine-local key file or vice versa. Derive a
32-byte wrapping key from the local key password using Argon2id and a fresh random
16-byte salt. Wrap the archive secret using XChaCha20-Poly1305 and a fresh random
nonce.

For each of opslimit and memlimit, use the local key's value or the default (3
passes, 256 MiB), whichever is larger. A `sensitive` local key (4 passes, 1 GiB) never
yields a cheaper embedded copy of the same password, and an `interactive` one is
raised to the default. Bundle key-password changes keep the bundle's current costs,
raised to the default if lower.

Associated data is `DOCVAULT-7Z-RECOVERY`, followed by one zero byte, followed by
canonical JSON of the format, version, inner digest and size, envelope ID and KDF
parameters. Exclude nonce and ciphertext from that body; changing either still
causes authentication failure. Reuse existing primitives with this new schema;
the current local-envelope schema does not bind an archive digest.

Bind the digest to the inner member, not the entire outer file, avoiding a circular
dependency. Outer filenames and timestamps are not part of that binding. Optional
public password hints use `NAME__KEY-HINT__7Z-HINT.7z`; the first group describes
the envelope/key password, and the second the outer password. Both are displayed
before credential entry. Hints are not authenticated and do not affect derivation,
the embedded key format or the authenticated document root. Legacy `NAME.7z`
bundles remain supported.

Bound `key` to 16 KiB. Enforce exact fields, types, version, algorithms, fixed binary
lengths and existing KDF bounds (2–16 passes, 64 MiB–4 GiB) before deriving. Costs up
to the `sensitive` profile need no approval, because DocVault creates them. Costs
above it but within the bounds require explicit approval: interactive commands show
the costs and ask the user to type `ACCEPT` before deriving the embedded key, and scripts
pass `--allow-kdf-cost`. Retain secrets only for the operation; do not promise
complete memory erasure in Python.

## Safe verification

Freeze the outer file through a non-following open of a regular file into private
staging. List, test and extract from that frozen input, not a mutable original path.
After unlocking headers with the derived outer key, require exactly `encrypted.7z`
and `key` at the root: regular files using the Copy method with encryption enabled.
Reject extra members, directories, duplicate or case-variant names, traversal,
links, alternative streams, unsupported methods and malformed headers. Require
encrypted outer headers as well as contents; a passworded listing alone does not
prove header encryption. Use bounded inspection that establishes this property
and fails closed. Never run unrestricted extraction of arbitrary outer members.

Apply limits to outer file size, declared member sizes and actual materialized
output. The inner member is bounded by the existing `2 * MAX_TOTAL_SIZE`; `key` by
16 KiB. Add a fixed 1 MiB outer allowance for headers, encryption overhead and
padding. Abort on overruns; bound subprocess resources and listing output too.
Staged members are mode `600` files in private directories. Their sensitive
payloads remain encrypted even after outer extraction. Never restore these wrapper
members as user documents.

Parse `key`, hash the same staged inner file that will be verified, and compare its
digest and size. Authenticate the envelope with the second password. Then perform
existing full inner extraction, metadata authentication, checksums, path validation,
permissions restoration and exclusive publication. Outer CRC checks or a digest
match alone do not authenticate documents.

Report first-layer failure as “wrong 7z password or damaged outer archive” and
envelope failure as “wrong local 7z key password or damaged embedded key.” Distinguish
layout and digest errors. Do not silently fall back to other passwords, local keys
or recursive unwrapping. Create user-owned mode `600` bundles without inherited
ACLs; retain existing filesystem and backup-exclusion requirements for plaintext.

## Single-file publication

All creation, update and password-change operations share the same
per-archive lock. Build and verify the entire replacement before publishing:

1. Build and fully verify `encrypted.7z`, or freeze and verify existing inner bytes
   when changing passwords.
2. Hash the inner bytes, create `key`, reopen it with the local key password and
   confirm the recovered secret matches the intended secret.
3. Package exactly the two members with the derived outer 7z key, using outer content
   and header encryption, Copy methods, no solid compression and no enclosing
   directory.
4. Reopen through the production reader with the outer password and then local key
   password. Validate the layout and entire inner archive. For document encryption,
   compare restored contents with the recorded source snapshot.
5. Flush the staged outer file. Publish a new output without overwriting, or
   atomically replace a verified existing output; flush its parent directory.
   Never unlink the old output before replacement.
6. Recheck source identity/content before conservative plaintext cleanup. Password changes never delete user documents.

An interrupted update leaves either the old complete output or the new complete
output. Failed durability barriers report uncertain publication and stop cleanup.
Preserve useful staged files and remaining plaintext. Do not automatically delete
old outputs or original documents on verification/publication failure. A staged
bundle is a candidate, never automatic authority; verify it before resumed use.

For current-directory operations exclude only the generated outer archive, during encryption.
Source documents named `key` or `encrypted.7z` remain documents; those names are
reserved only inside the wrapper. Decryption requires only its bundle in the
directory and restores documents beside it.

## Password changes and security scope

Management commands select the credential being changed:

```sh
docvault bundle passwd /path/to/Documents.7z --layer outer
docvault bundle passwd /path/to/Documents.7z --layer key
```

Both first ask `Local 7z key password: ` and `Enter 7z password: `, fully verify the
bundle, then print the duplication warning and request and confirm the selected new
password. Print its strength report and the whole-bundle line. The new password must
pass the strength floor and the similarity rule against the other layer's current
password. Invalid new terminal entries can be retried until accepted or cancelled. Outer-password changes rebuild the outer file with both member bytes
unchanged. Key-password changes generate a fresh salt, nonce and envelope ID, then
rebuild using the current outer password. Preserve `encrypted.7z` byte for byte in
both cases and publish atomically. Rebuilding requires temporary disk space for the
replacement and verification; it does not re-encrypt document contents.

The existing `docvault passwd` changes only the machine's key file. It does not
update existing bundles, which still need their previous embedded-key password.
Changing a bundle key password does not change the machine's key file. Old copied
bundles retain old passwords. Revoking an exposed archive secret requires a new
secret and document re-encryption.

These are two password layers, not two-factor authentication. Attackers crack the
outer password first and then the embedded-key password. The times add; do not
multiply both password search spaces to estimate strength. Both layers use Argon2id
at least at the default cost, so with two passwords of equal strength a bundle takes
about twice as long as one layer. Each password must also stand on its own: anyone
who knows the outer password, such as a recipient it was shared with, faces only the
embedded key. Once members have been extracted, the outer password does not protect
those extracted copies. Retain both passwords independently of the laptops. Sudo
and prompt limits do not prevent offline guessing. Complete older valid bundles can
be substituted; version 1 has no external freshness record.

## Offline guessing cost

A bundle is protected by two passwords, so it is only as strong as they are.
The random archive secret is carried inside the password-protected embedded key.

Model: the fastest system on the June 2026 TOP500 list, LineShine (2.198 EF), uses
CPUs only. Password guessing depends on integer work and memory bandwidth, not the
floating-point performance TOP500 ranks, and there the GPU-based El Capitan (No. 2:
44,544 AMD MI300A, 5.3 TB/s of memory bandwidth each) is faster. Each default
Argon2id guess moves about 2 GiB of memory, so El Capitan's peak bandwidth caps
guessing at about 1.1 × 10^8 per second per layer. That is a generous ceiling: real
GPU Argon2id implementations reach far less, and LineShine would take several times
longer. Guessing a `sensitive` embedded key is about 5.5 times slower.

Average time to find a password (half the search space):

| Password | Bits | One layer | Both layers this strong |
|---|---|---|---|
| Human-chosen, in a 10^10-guess wordlist | — | ~90 seconds | ~3 minutes |
| 4 random words (7,776-word list) | 51.7 | 193 days | 385 days |
| 8 random printable characters | 52.6 | 350 days | 700 days |
| 10^18 estimated guesses, the refusal floor | 60.8 | 105 thousand days (290 years) | 210 thousand days |
| 5 random words | 64.6 | 1.5 million days (4,100 years) | 3.0 million days |
| 10 random printable characters | 65.7 | 3.2 million days (8,600 years) | 6.3 million days |
| 10^21 estimated guesses, the recommended minimum | 70.8 | 105 million days (290 thousand years) | 210 million days |
| 12 random letters and digits | 71.5 | 170 million days (465,000 years) | 340 million days |
| 6 random words (`--generate-password`) | 77.5 | 11.6 billion days (32 million years) | 23 billion days |
| 12 random printable characters | 78.8 | 28.5 billion days (78 million years) | 57 billion days |

These rows assume randomly chosen passwords; the [strength report](#strength-report)
estimates the password actually typed. Aim for the recommended 10^21 guesses per
layer: six random words, or twelve or more random characters from a password manager.
Hardware keeps getting faster, and archives are kept for years. Passing the typed
outer password straight to 7z would make the outer column about 50 times shorter.

What a bundle exposes beyond its own documents:

- Anyone who obtains a bundle and its outer password can guess the embedded-key
  password offline.
- A local key shares one random secret across bundles. Cracking one bundle's
  passwords reveals the secret and exposes every bundle made with that key.
  Digest binding prevents mismatches but does not isolate archive secrets.
- The crack also reveals the local password used when the key was embedded,
  which can unlock copies of that machine-local key file.

Use separate local keys when bundles require independent archive secrets.

## Implementation

Only the encrypted two-member bundle format is accepted. Opening malformed layouts
fails closed; no alternative format, local key or password strategy is attempted.
Fresh encryption requires a local key. Updating, decrypting or verifying a bundle
and changing its passwords use the embedded key without requiring the machine's key.

`--outer-password-fd FD` supplies the outer credential and `--password-fd FD` the
local/embedded-key credential. Password changes accept separate new-password
descriptors, requiring two matching entries. `--generate-password` generates a
new outer or selected bundle password. `--allow-kdf-cost` explicitly approves
embedded costs above the sensitive profile. 7z receives only hexadecimal secrets
through protected pipes, never typed passwords, arguments, environment variables,
logs or password files.

The implementation shares strict JSON, cryptography, inner verification, locks,
restoration and durability primitives. Staging accounts for frozen input, inner
ciphertext, replacements and verified plaintext. Insufficient disk space stops
processing while retaining originals.

Regression coverage includes the following release checks:

- Exact no-argument local-first two-prompt flow; failed outer entries retry
  without repeating the local prompt. No third application password.
- Outer derivation matches the test vector. 7z receives only the derived key, never
  the typed password, and plain 7z with the typed password cannot open the bundle.
- Equal, case- or space-variant, containing and near (edit distance 4 or less)
  passwords are refused by `encrypt`, bundle updates
  and both `bundle passwd` layers, before any archive is published, for
  terminal and descriptor input alike.
- Strength floor and recommendation for new outer and embedded-key passwords, and
  for the local key password when first embedded; generated passphrases must be
  typed back.
- Strength reports match the calibration examples, take the lowest of the three
  attacks, use the layer's KDF costs, go only to stderr and never describe the
  password's structure. The duplication warning always precedes the local
  password prompt.
- Embedded KDF costs are the larger of the local key's and the default; costs above
  `sensitive` need approval; costs beyond the bounds fail before deriving.
- Encrypted outer contents and headers, exactly two root members, one wrapper level
  and no external recovery file.
- Transfer and rename to a laptop with missing/unrelated local keys; restore using
  the two bundle passwords without changing the receiver's key.
- Recovery after local-key loss; safe failure for either incorrect password.
- Password changes preserve inner ciphertext; credential changes
  are independent and old bundles retain old passwords.
- Reject malformed/unencrypted wrappers, unsafe paths, links, duplicates, excessive
  sizes/KDF costs, modified envelopes and mismatched inner bytes. Freeze inputs
  against substitution between listing, hashing and extraction.
- Verify both layers before publishing; inject crashes and durability failures,
  retain complete outputs and stop plaintext cleanup on reported failures.
- Current-directory operations, spaces, renaming, source files named `key` or
  `encrypted.7z`, metadata restoration and overwrite refusal.
- Custom keys and missing or unrelated receiver keys; all bundle processing and
  7z execution run without root privileges.
