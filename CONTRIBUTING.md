# Contributing

DocVault currently supports macOS and Python 3.12 or later. Install modern 7-Zip
and uv, then prepare the development environment:

```sh
brew install python@3.12 uv sevenzip
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e '.[test]'
.venv/bin/python -m pytest -q
```

Open an issue for a bug or proposed change, or submit a focused pull request.
Include reproduction steps, macOS/Python/7-Zip versions, and relevant test results.
Use synthetic documents and redact paths, passwords, hints and key material.
Follow [SECURITY.md](SECURITY.md) for vulnerabilities.

Changes to archive formats, password handling, privileged launchers or plaintext
cleanup need regression coverage and matching updates to the recovery documentation.
Most tests replace the expensive KDF for speed; tests marked `real_kdf` exercise
Argon2id. Run the full suite before submitting those changes.

The installer uses an editable environment. Keep the checkout and `.venv` in
place, and rerun `./install.sh` after changes to installed sudo launchers.

To regenerate the installation and usage GIF/video, see [docs/demo.md](docs/demo.md).
Contributions to original project code are accepted under the MIT License.
