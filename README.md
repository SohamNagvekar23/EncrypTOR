# EncrypTOR

A Python encryption toolkit (command line and a Tkinter desktop GUI) with two modes and a cryptanalysis demo:

- `classic`: a running-key cipher whose keystream is the hex digits of pi, computed with the Bailey-Borwein-Plouffe (BBP) formula, starting at a secret offset derived from a passphrase.
- `secure`: ChaCha20-Poly1305 authenticated encryption with a scrypt-derived key, using the `cryptography` library.
- `crack`: recovers the classic-mode offset from one known plaintext/ciphertext pair, to show why classic mode is not secure.

> **Classic mode is an educational cipher and is NOT secure.** Do not use it to protect anything. It exists to show how a running-key cipher works and how quickly it breaks. **Use `--mode secure` for real data.**

Runtime dependencies: the Python standard library and `cryptography`. Nothing else.

## Contents

- [Install](#install)
- [Tests and linters](#tests-and-linters)
- [Usage](#usage)
- [GUI](#gui)
- [How classic mode works](#how-classic-mode-works)
- [Why classic mode is insecure](#why-classic-mode-is-insecure)
- [Why secure mode is safe](#why-secure-mode-is-safe)
- [Performance](#performance)
- [Known limitations and usage warnings](#known-limitations-and-usage-warnings)
- [Project layout](#project-layout)

## Install

Requires Python 3.11 or later.

```bash
# for development (adds pytest, ruff and mypy)
pip install -e ".[dev]"

# or just the tool
pip install .
```

This installs one command, `encryptor`:

- `encryptor encrypt | decrypt | crack ...` is the command-line tool. `python -m encryptor.cli ...` is equivalent.
- `encryptor` with no arguments opens the desktop GUI. `python -m encryptor.gui` is equivalent. The GUI code is imported only in that case, so CLI start-up is unaffected. On Windows, launching it from a shortcut also opens a console window, because `encryptor` is a console command.

The GUI uses Tkinter, which is part of the standard library and adds no dependency. Some Linux distributions package it separately; if `python -c "import tkinter"` fails, install the system package (for example `sudo apt install python3-tk` on Debian and Ubuntu, `sudo dnf install python3-tkinter` on Fedora). Without a display, `encryptor` (no arguments) prints `encryptor: no display available` and exits with code 1.

## Tests and linters

```bash
pytest -q
ruff check .
mypy --strict src
```

Current results (CPython 3.13.15, `cryptography` 50.0.0, Windows 11):

```text
981 passed, 2 skipped in 113.46s
All checks passed!
Success: no issues found in 12 source files
```

The GUI smoke tests build the real window and are skipped when no display is available. On the development machine, Tk's initialisation intermittently fails under pytest (`Can't find a usable init.tcl`, a Tcl library file read failure), which is reported as "no display available"; that is where the 2 skips above come from. The same tests pass when run alone or with `pytest -s`.

The suite covers round trips in both modes (empty input, one character, long text, emoji and other non-ASCII UTF-8), the pi digits against a 64-digit golden vector and an independent reference implementation, batched against single-digit output, chaining, wrong passphrases, a flip of every single bit of a secure-mode ciphertext, the crack search (hit, clean miss, progress callback and stopping), the CLI (argument and stdin input, `--decimal`, bad input, missing passphrase, exit codes, closed pipes), and the GUI: controller unit tests without a display (round trips, error mapping, cancel, output wrapping) and smoke tests on the real window (shortcuts, passphrase clearing and masking, Clear during a job).

## Usage

```text
encryptor encrypt --mode {classic,secure} [--decimal] (--passphrase P | --prompt) [TEXT | -]
encryptor decrypt --mode {classic,secure} [--decimal] (--passphrase P | --prompt) [HEX | -]
encryptor crack   [--max-offset N] --plaintext TEXT --ciphertext HEX
```

- The input is the positional argument. If it is `-` or omitted, input is read from standard input.
- Exactly one of `--passphrase P` or `--prompt` is required. `--prompt` reads the passphrase from the terminal without echo.
- `encrypt` prints hex. `--decimal` (classic mode only) prints, and on `decrypt` reads, space-separated decimal byte values.
- `encryptor --help` and `encryptor COMMAND --help` describe every option.

All output below is real, captured in Git Bash on Windows. `$` is the shell prompt. The passphrases are examples; do not reuse them.

### Where output goes

| Output | Stream |
|---|---|
| Result of `encrypt` (hex or decimal), `decrypt` (the text) and `crack` (three lines) | stdout |
| The classic-mode warning, once per classic `encrypt`, classic `decrypt` and `crack` run | stderr |
| Error messages (`encryptor: error: ...`) and usage errors | stderr |
| `--help` | stdout |

So stdout can be piped or captured without the warning in it. The passphrase and the offset derived from it are never printed (the `crack` command prints the offset it recovers, which is its purpose).

### Classic mode (educational, not secure)

```console
$ encryptor encrypt --mode classic --passphrase pi-demo-78 "Hello, pi!"
WARNING: classic mode is an educational cipher and is NOT secure. Use --mode secure for real data.
4cb09b44bafa2d553dee

$ encryptor decrypt --mode classic --passphrase pi-demo-78 4cb09b44bafa2d553dee
WARNING: classic mode is an educational cipher and is NOT secure. Use --mode secure for real data.
Hello, pi!
```

The warning is on stderr. With stderr discarded, only the result remains:

```console
$ encryptor encrypt --mode classic --passphrase pi-demo-78 "Hello, pi!" 2>/dev/null
4cb09b44bafa2d553dee
```

Decimal output and input (classic mode only). The stderr warning is omitted from the remaining classic examples.

```console
$ encryptor encrypt --mode classic --decimal --passphrase pi-demo-78 "Hello, pi!"
76 176 155 68 186 250 45 85 61 238

$ encryptor decrypt --mode classic --decimal --passphrase pi-demo-78 "76 176 155 68 186 250 45 85 61 238"
Hello, pi!
```

Repeated plaintext characters do not give a repeating ciphertext, because each byte is chained to the previous ciphertext byte:

```console
$ encryptor encrypt --mode classic --passphrase pi-demo-78 "aaaaaaa"
659dbb69999402
```

### Secure mode

```console
$ encryptor encrypt --mode secure --passphrase "correct horse battery staple" "Meet at noon."
0157c205e04566d1de2d96c31404bf47e6acb0dd6897b3828d4f0b2039f7c4d091ea7ab6e85c5204e4b73062fe963c08152089e20fd9ba297735

$ encryptor decrypt --mode secure --passphrase "correct horse battery staple" 0157c205e04566d1de2d96c31404bf47e6acb0dd6897b3828d4f0b2039f7c4d091ea7ab6e85c5204e4b73062fe963c08152089e20fd9ba297735
Meet at noon.
```

Every encryption uses a fresh random salt and nonce, so encrypting the same text again gives a different result (your output will differ from the one above too):

```console
$ encryptor encrypt --mode secure --passphrase "correct horse battery staple" "Meet at noon."
01d33e335ffe615c2087cbe51626b25f462efffdd623f456b395ea355e0e0313cae2d7538b384208b021931a19210473520f28435c57c93e585f
```

### Input from standard input

Use `-` or leave the positional argument out.

```console
$ printf 'piped text' | encryptor encrypt --mode classic --passphrase pi-demo-78 -
7484b36590dc5f324bcd

$ printf 'piped text' | encryptor encrypt --mode classic --passphrase pi-demo-78 2>/dev/null | encryptor decrypt --mode classic --passphrase pi-demo-78 2>/dev/null
piped text
```

On `encrypt`, standard input is taken exactly as it is and must be valid UTF-8. A trailing newline is part of the message: `echo "text" | encryptor encrypt ...` encrypts `text` plus a newline. On `decrypt`, surrounding whitespace around the hex or decimal text is ignored.

### Passphrase prompt

```console
$ encryptor encrypt --mode secure --prompt "Meet at noon."
Passphrase:
```

The passphrase is read with `getpass` and is not echoed; the hex result is then printed as above. This interaction needs a real terminal, so it was not captured for this README (the test suite covers `--prompt` with a substituted `getpass`). Prefer `--prompt` to `--passphrase`: a passphrase given on the command line is visible in shell history and process lists.

### Crack demo

```console
$ encryptor encrypt --mode classic --passphrase "correct horse" "Attack at dawn, bring coffee." 2>/dev/null
5d1c1300e61353ce7473bbea4d32266d12ae9688131d60f3e8e1b6e7d3

$ encryptor crack --plaintext "Attack at dawn, bring coffee." --ciphertext 5d1c1300e61353ce7473bbea4d32266d12ae9688131d60f3e8e1b6e7d3
WARNING: classic mode is an educational cipher and is NOT secure. Use --mode secure for real data.
offset: 87601
candidates tried: 87602
elapsed: 2.889 s
```

`--max-offset N` limits the search to offsets `0` to `N-1` (default: the whole range, 2^17). If the offset is not in the range the command fails cleanly:

```console
$ encryptor crack --max-offset 4096 --plaintext "Attack at dawn, bring coffee." --ciphertext 5d1c1300e61353ce7473bbea4d32266d12ae9688131d60f3e8e1b6e7d3
WARNING: classic mode is an educational cipher and is NOT secure. Use --mode secure for real data.
encryptor: error: offset not found in [0, 4096) after 4096 candidates (0.006 s)
```

That run exits with code 5.

### Errors and exit codes

Expected failures print one line on stderr and never a traceback. A wrong secure-mode passphrase:

```console
$ encryptor decrypt --mode secure --passphrase "wrong passphrase" 0157c205e04566d1de2d96c31404bf47e6acb0dd6897b3828d4f0b2039f7c4d091ea7ab6e85c5204e4b73062fe963c08152089e20fd9ba297735
encryptor: error: authentication failed: wrong passphrase, or the data was corrupted or tampered with
$ echo $?
4
```

Changing a single hex digit of that ciphertext and decrypting with the right passphrase gives the same line and the same exit code. Other examples:

```console
$ encryptor decrypt --mode classic --passphrase pi-demo-78 zz
encryptor: error: invalid hex input: expected an even number of hex digits (0-9, a-f)

$ encryptor decrypt --mode secure --passphrase x 01ab
encryptor: error: ciphertext is too short to be valid

$ encryptor encrypt --mode secure --decimal --passphrase x hi
usage: encryptor [-h] COMMAND ...
encryptor: error: --decimal is only available with --mode classic
```

These exit with 3, 3 and 2.

| Code | Meaning |
|---|---|
| 0 | Success (also `--help`) |
| 1 | Any other error (for example not enough memory for scrypt), or standard output is a closed pipe |
| 2 | Usage error: missing or conflicting options, empty passphrase, `--decimal` with `--mode secure`, unexpected extra arguments, invalid `--max-offset`, `--prompt` with no terminal to read from |
| 3 | Bad input: invalid hex or decimal text, input that is not valid UTF-8 (or not ASCII on `decrypt`), a secure-mode ciphertext that is too short or has an unknown version byte, classic decryption that does not give valid UTF-8, empty or unequal-length `crack` inputs |
| 4 | Secure mode authentication failed: wrong passphrase, or corrupted or tampered data |
| 5 | `crack`: no offset in the searched range matches |
| 130 | Interrupted with Ctrl-C (`encryptor: error: interrupted`) |

A closed stderr never changes the exit code.

## GUI

```bash
encryptor
# or
python -m encryptor.gui
```

A thin Tkinter + ttk front end with a dark theme (ttk's `clam` theme, recoloured, so it looks the same on Windows, macOS and Linux rather than native). It calls the same `classic`, `secure` and `crack` functions as the CLI, in the same process; it contains no cryptography of its own and does not run the CLI. The display-free logic (validation, core calls, error mapping, worker jobs) is in `src/encryptor/gui/controller.py`, the widgets in `app.py`. Minimum window size 720 x 540.

### Encrypt / Decrypt tab

- **Action**: Encrypt or Decrypt. **Mode**: Secure (the default) or Classic.
- **Classic banner**: while Classic is selected, a persistent banner reads "Classic mode is educational and NOT secure. Use secure mode for real data."
- **Decimal output/input (classic only)**: enabled only in classic mode; encrypt then shows space-separated byte values and decrypt reads them. Otherwise output and input are hex.
- **Passphrase**: a masked field with a **Show** toggle and a **Keep passphrase** check box (see [GUI security notes](#gui-security-notes)).
- **Input** and **Output** text areas. Encrypt output is displayed in lines of at most 64 characters (decimal values are never split); decrypt ignores those line breaks, and spaces, tabs and newlines in pasted hex.
- **Run**, **Swap output into input** (moves the displayed output into the input and clears the output; it does not switch Encrypt/Decrypt), **Clear** (clears input, output and passphrase), **Copy** (copies the output, unwrapped, to the clipboard).
- An indeterminate progress bar runs while the operation is on the worker thread (secure mode spends about 0.25 s in scrypt).

### Crack demo tab

- The same "educational, NOT secure" banner, shown permanently.
- **Known plaintext** and **Its classic-mode ciphertext (hex)**. Line breaks and spaces in the hex are ignored, so the wrapped output of the other tab can be pasted as is.
- **Max offset**: blank searches the full range (131072); otherwise a whole number from 1 to 131072. The search covers offsets `0` to `max - 1`, as `--max-offset` does.
- **Run**, **Cancel**, **Clear**.
- A progress bar with the text "ruled out offsets below X of Y". The bar is weighted by estimated work rather than by offsets (`(X/Y)^2`, because generating pi digits up to position d costs about O(d^2) in total), so it moves roughly evenly in time.
- **Result**: the same three lines the CLI prints (`offset`, `candidates tried`, `elapsed`), or the not-found message. Cancel takes effect at the next digit chunk, within about 1 s (see [GUI benchmarks](#gui-benchmarks)).

### Keyboard shortcuts

| Action | Windows and Linux | macOS |
|---|---|---|
| Run the selected tab | Ctrl+Enter (main or keypad Enter) | Cmd+Enter or Ctrl+Enter |
| Clear the selected tab | Ctrl+L | Cmd+L or Ctrl+L |

The button labels show the shortcut for the platform. Ctrl+Enter inside a text area runs the operation without inserting a newline.

### Errors

Expected failures are shown as a dialog with a short title and message, never a traceback. For example, a wrong secure-mode passphrase or tampered data gives "Decryption failed: Wrong passphrase, or the data was corrupted or tampered with. Nothing was decrypted."; bad hex, empty input or a missing passphrase give "Invalid input"; malformed secure-mode data gives "Incomplete ciphertext" or "Unsupported format". An unexpected exception shows only its type name. A crack that finds nothing shows the not-found message in the Result box instead of a dialog.

### GUI security notes

- **Masked passphrase.** The field shows `*`. **Show** reveals it; it is masked again automatically at each run and on Clear. Copy and Cut are blocked in the field, and its selection is not exported (no X11 PRIMARY selection), so it cannot leave through the clipboard. The output area does not export its selection either; **Copy** is the explicit way to take output out.
- **Cleared after each run.** When Run passes the quick input checks, the passphrase is removed from the field as the operation starts, unless **Keep passphrase** is checked. If those checks fail (for example invalid hex), the passphrase stays so it does not have to be retyped. Clear and Ctrl+L always remove it.
- **Never logged or written to disk.** The GUI has no logging and no settings or history file, and never puts the passphrase in a dialog, the status line, a window title or a `repr`. It is handed to the worker in one request object, which is dropped when the operation ends.
- **Work runs off the UI thread.** scrypt, classic-mode encryption and the crack search run on a worker thread; the UI polls for results with `root.after` and stays responsive. Clear during a running encrypt/decrypt discards its result (scrypt cannot be interrupted, so a new run waits until that worker has finished). Closing the window stops a running crack; worker threads are daemon threads and end with the process.
- **Limitation: secrets in memory.** Python strings are immutable and Tk keeps its own copy of the entry text, and neither can be zeroed. The passphrase (and the plaintext) can therefore stay in process memory until it is garbage-collected and the memory reused. This is the same as in the CLI; protecting against someone who can read the process memory is out of scope.
- Classic mode in the GUI is exactly as insecure as in the CLI.

## How classic mode works

Classic mode is NOT secure. This section explains the mechanism; the next one explains how it breaks.

```text
passphrase (UTF-8)
    |  SHA-256, read as a big-endian integer, mod 2^17
    v
offset: a position in the hex digits of pi, in [0, 131072)
    |  BBP formula: hex digits of pi from that position on
    v
key bytes: two hex digits per byte, high nibble first
    |
    v
c[i] = p[i] XOR k[i] XOR c[i-1]        with c[-1] = 0xA5
```

1. **Plaintext** is the UTF-8 bytes of the text.
2. **Offset.** `offset = SHA-256(passphrase) mod 2^17` (`classic.OFFSET_BOUND`, one constant). The offset counts hex digits after the point; position 0 is the `2` of `3.243F6A88...`. Odd offsets are valid.
3. **Keystream.** Key byte `i` is `16 * digit[offset + 2i] + digit[offset + 2i + 1]`.
4. **Chaining.** `c[i] = p[i] XOR k[i] XOR c[i-1]`, where the byte before the first one is the fixed constant `0xA5` (`classic.CHAIN_IV`). Decryption is `p[i] = c[i] XOR k[i] XOR c[i-1]`. Output length equals input length.

Worked example at offset 0, where the key bytes are `24 3F 6A 88 ...` (checked by running `classic.encrypt_at_offset(b"Hi!", 0)`, which returns `c99fd4`):

| i | p[i] | k[i] | c[i-1] | c[i] = p XOR k XOR c[i-1] |
|---|---|---|---|---|
| 0 | `48` (H) | `24` | `A5` | `C9` |
| 1 | `69` (i) | `3F` | `C9` | `9F` |
| 2 | `21` (!) | `6A` | `9F` | `D4` |

### The pi digits (BBP)

The BBP formula is

```text
pi = sum over k >= 0 of 16^-k * ( 4/(8k+1) - 2/(8k+4) - 1/(8k+5) - 1/(8k+6) )
```

The hex digits from position `d` onward are the digits of `frac(16^d * pi)`, and the terms with `k <= d` can be reduced with modular exponentiation, so digits at position `d` can be computed without computing the ones before them. The implementation is in `src/encryptor/pi_stream.py`:

- **Integer fixed point, no floats.** A double has 53 mantissa bits and gives no usable error bound; Python integers give a provable one at any width. A request for `c` digits with `G` guard bits is carried with `P = 4c + G` fractional bits.
- **A batch of digits per evaluation.** `pi_hex_int(position, count)` returns `count` digits from one evaluation (default 8, `HEX_DIGITS_PER_BATCH`). Reaching position `d` dominates the cost, so 8 digits cost the same as 1 (see the benchmark table). The keystream asks for up to 4096 digits per evaluation (`KEYSTREAM_BLOCK_DIGITS`, 2 KiB of key bytes), and never for more digits than the message needs.
- **Grouped terms.** The four parts of term `k` are one positive fraction `n(k)/m(k)` with `n = 120k^2 + 151k + 47` and `m = 512k^4 + 1024k^3 + 712k^2 + 194k + 15`. Eight consecutive terms (`_GROUP_TERMS`) are combined into one exact fraction, so a group costs one modular exponentiation and one wide division instead of one of each per part.
- **Guard bits and the acceptance rule.** Each group is floored once, so the computed sum is never above the true value and is below it by less than a known bound. The code uses the loose bound `E = 8 * (d + P)`. A batch is accepted only if its low `G` bits `g` satisfy `E <= g < 2^G - E`; then the rounding error cannot carry or borrow into the digits that are returned. `G` starts at 64 bits (`GUARD_BITS`).
- **Doubling fallback.** If the rule rejects a batch, `G` is doubled and the batch is recomputed, up to 1024 bits (`MAX_GUARD_BITS`), after which a `PrecisionError` is raised. A rejection needs a long run of `0` or `F` digits right after the batch, so this path is practically unreachable; the tests force it with a tiny guard to check that the result is still correct.

How it is tested:

- **Golden vector.** The first 64 hex digits, `243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89`, at offset 0 and by slicing at non-zero offsets, even and odd.
- **Independent reference.** The test file computes pi with Machin's formula (`16*atan(1/5) - 4*atan(1/239)`) in integer fixed point, which shares nothing with BBP, and compares far positions and a whole 16,448-digit batch against it.
- **Batched equals single digit.** `pi_hex_digit` is a deliberately separate, plain BBP loop (no grouping, no shared code). Batched output must equal it digit by digit, including across group boundaries and with the fallback forced.

## Why classic mode is insecure

- **Tiny key space.** Whatever the passphrase, the key is one of 2^17 = 131,072 offsets. All of them can be tried in seconds.
- **Public keystream.** The keystream is a window of the hex digits of pi, which anyone can compute. The only secret is where the window starts.
- **Known plaintext gives the keystream directly.** From one plaintext/ciphertext pair, `k[i] = p[i] XOR c[i] XOR c[i-1]`. No pi computation is needed. Chaining hides repeated letters but adds no secrecy, because `c[i-1]` is itself ciphertext.
- **No integrity.** Nothing detects a modified ciphertext; flipping a ciphertext bit flips the same plaintext bit (and one in the next byte).
- **A wrong passphrase is undetectable** by the cipher. Decryption just returns different bytes.
- **Passphrase strength is irrelevant.** A long random passphrase still maps to one of 131,072 offsets.

### The crack demo

`encryptor crack` turns the points above into a search: it derives the keystream from the known pair, writes it as hex digits, and looks for that string in the digits of pi.

- The digits of the search range are generated once, in increasing position, 16,384 per BBP evaluation (`CRACK_CHUNK_DIGITS`), into one table. Candidates are consecutive positions in that table, so nothing is recomputed per candidate.
- Each candidate is tested on a 4-byte prefix (8 hex digits, `CRACK_PREFIX_BYTES`) with a substring search. A wrong offset survives that with probability 2^-32. The full message is compared only on a prefix match.
- The search stops at the first full match, so later chunks are never generated.
- `crack.crack(plaintext, ciphertext, max_offset=None, *, progress=None)` takes an optional keyword-only callback `progress(tried, total) -> bool`. With a callback, digits are generated in chunks of 12,288 (`CRACK_PROGRESS_CHUNK_DIGITS`) and the callback runs once per chunk and while a prefix hit is being extended; returning `False` stops the search with `CrackStoppedError`. The GUI uses it for its progress bar and Cancel. The CLI does not pass it, so its path is unchanged.

Real output, for a ciphertext made with the passphrase `correct horse` (commands in [Crack demo](#crack-demo) above):

```text
offset: 87601
candidates tried: 87602
elapsed: 2.889 s
```

The time varies with the offset (cost grows with roughly the square of it) and with the machine's state. Searching the entire range, whether the offset is the last candidate or not present at all, took 5.0 to 5.3 s in the benchmark below.

## Why secure mode is safe

Secure mode contains no custom cryptography. `src/encryptor/secure.py` calls `ChaCha20Poly1305` and `Scrypt` from the `cryptography` library and `os.urandom`; it implements no cipher, MAC, key derivation or comparison of its own.

- **Authenticated encryption.** ChaCha20-Poly1305 is an AEAD: it encrypts and produces a 16-byte tag over the ciphertext and the associated data. Decryption verifies the tag before returning anything.
- **Key derivation.** The 32-byte key is derived from the passphrase with scrypt, `N = 2^17`, `r = 8`, `p = 1` (`SCRYPT_N`, `SCRYPT_R`, `SCRYPT_P`). That costs 128 MiB of memory (`128 * N * r` bytes) and about 0.25 s per derivation on the benchmark machine, for the legitimate user and for every guess an attacker makes. This setting is the first of the scrypt configurations listed in the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt) (that guidance is written for password storage; here the same parameters are used to derive an encryption key).
- **Random salt and nonce per message.** A fresh 16-byte salt and 12-byte nonce from `os.urandom` for every encryption. The salt gives every message its own key, so a nonce is never reused under one key, and two encryptions of the same input differ.
- **Authenticated header.** The 29-byte header (version, salt, nonce) is passed as associated data, so changing any header byte fails authentication.
- **Format**, output as hex:

  ```text
  version (1 byte, = 1) || salt (16) || nonce (12) || ciphertext || tag (16)
  ```

  The output is 45 bytes longer than the plaintext.
- **Failure behaviour.** A wrong passphrase or any modification raises an authentication error (exit code 4). Unauthenticated plaintext is never returned. The tests flip every single bit of a ciphertext in turn: a flip in the version byte is rejected as an unsupported version, every other flip as an authentication failure. An empty or too-short input, or an unknown version byte, is rejected before any key derivation (exit code 3).

Limits:

- **Passphrase strength still matters.** scrypt makes each guess expensive; it does not make a weak passphrase strong.
- **The whole message is held in memory.** The AEAD is one-shot and the format has one tag, so secure mode is not streaming. Encryption holds about twice the message size in Python memory (the result is joined to the header with one copy), decryption about once, plus the 128 MiB scrypt work area.
- **`--passphrase` exposes the passphrase** to shell history and process lists. Use `--prompt`.
- The tool does not protect against a compromised machine, and it has had no external audit. It is a portfolio project.

## Performance

### Complexity

- **BBP has no cheap "next digits" step.** Every evaluation at digit position `d` pays for its position again, roughly O(d log d) for a short batch (precisely O((d + c)(log d + c/w)) for `c` digits and machine word `w`). Classic mode therefore does not run in "O(n) after the initial offset cost". Its keystream costs a fixed number of evaluations per 2 KiB of message, `ceil(2n / 4096)` in total, each at a position that grows with the offset and with the message. It is practical for short messages (up to a few KiB), not for large files.
- **The XOR and chaining layer** is O(n) time. Through the chunk API (`classic.encrypt_chunks` / `decrypt_chunks`) it uses O(1) extra memory: one key block of at most 2 KiB and one chain byte.
- **The one-shot API** (`encrypt_at_offset` / `decrypt_at_offset`, which the CLI uses) holds the output plus a small margin: 1.06 times the output at 16 MiB.
- **Secure mode** is O(n) time plus the fixed scrypt cost, and O(n) memory.
- **Crack** generates at most `max_offset + 2m` digits for an `m`-byte message; its time grows with roughly the square of the offset found, its memory is one byte per digit generated.

### Benchmarks

Measured on a 13th Gen Intel Core i7-13620H laptop (6 performance + 4 efficiency cores, 24 GB), Windows 11 Home 10.0.26200, Balanced power plan on AC, CPython 3.13.15, `cryptography` 50.0.0.

Conditions: one process; Windows power throttling disabled for the benchmark process; CPU not heat-limited; every case run 3 to 5 times; times are "min / median" of wall time; memory is the `tracemalloc` peak of a separate run. `us` means microseconds.

These are best-case figures for this machine. Under sustained load the same laptop runs about 1.45 times slower, and a background or power-throttled process (anything that does not own the foreground window on Windows 11) runs a further 2.3 to 4 times slower.

To reproduce:

```bash
python benchmarks/bench_pi_stream.py
python benchmarks/bench_modes.py
python benchmarks/bench_crack.py
```

All three take about 3.5 minutes together. Add `--quick` for a reduced set, or `--no-qos` to measure the throttled case.

**One BBP evaluation** (min / median). Batching is free: 8 digits cost the same as 1.

| digit position | `pi_hex_digit` (1 digit, reference path) | 1 digit | 8 digits | 512 digits | 4096 digits |
|---|---|---|---|---|---|
| 0 | 4.8 / 5.9 us | 5.2 / 6.3 us | 6.4 / 6.6 us | 198 / 204 us | 4.7 / 4.7 ms |
| 1,024 | 1.4 / 1.4 ms | 517 / 525 us | 517 / 520 us | 912 / 917 us | 6.9 / 6.9 ms |
| 16,384 | 31.0 / 31.1 ms | 14.8 / 14.9 ms | 15.1 / 15.2 ms | 18.8 / 18.9 ms | 50.1 / 52.6 ms |
| 65,536 | 141.7 / 142.4 ms | 79.6 / 80.0 ms | 79.0 / 79.2 ms | 95.1 / 95.8 ms | 217.9 / 221.0 ms |
| 131,071 | 298.9 / 306.6 ms | 178.9 / 179.9 ms | 179.2 / 182.4 ms | 213.4 / 217.7 ms | 460.2 / 466.9 ms |

**Keystream throughput** in bytes per second, by digits per evaluation (rate at the min time; rate at the median in brackets). The default is 4096 digits (2 KiB of key per evaluation).

| offset | 8 digits | 512 digits | 4096 digits (default) |
|---|---|---|---|
| 0 | 399,002 (390,244) | 1,266,073 (1,014,263) | 440,345 (434,045) |
| 1,024 | 7,440 (7,356) | 279,080 (276,160) | 298,499 (295,958) |
| 16,384 | 271 (269) | 13,749 (13,656) | 40,743 (39,393) |
| 65,536 | 49.8 (48.5) | 2,641 (2,526) | 9,442 (9,324) |
| 131,071 | 22.0 (20.5) | 1,198 (1,185) | 4,217 (4,017) |

**Classic mode, encrypt, end to end** (min / median; decrypt is within 5% of encrypt). The offset comes from the passphrase and is uniform in [0, 131072).

| offset | 16 B | 256 B | 4 KiB | peak memory (4 KiB) |
|---|---|---|---|---|
| 0 | 15.7 / 17.7 us | 196 / 206 us | 19.2 / 19.6 ms | 21.4 KiB |
| 65,536 | 79.2 / 80.3 ms | 99.9 / 106.5 ms | 458.6 / 462.3 ms | 21.5 KiB |
| 131,071 (worst case) | 181.5 / 182.3 ms | 218.3 / 227.7 ms | 934.7 / 939.4 ms | 21.5 KiB |

**Classic cipher layer alone** (XOR and chaining with a synthetic keystream, no pi computation): linear time, constant extra memory for the chunk API.

| input | API | min / median | per byte | peak memory |
|---|---|---|---|---|
| 64 KiB | `encrypt_chunks` | 0.55 / 0.71 ms | 8.5 ns | 14.8 KiB |
| 1 MiB | `encrypt_chunks` | 7.6 / 7.6 ms | 7.2 ns | 14.8 KiB |
| 16 MiB | `encrypt_chunks` | 123.7 / 132.3 ms | 7.4 ns | 14.8 KiB |
| 64 KiB | `decrypt_chunks` | 0.33 / 0.35 ms | 5.1 ns | 16.8 KiB |
| 1 MiB | `decrypt_chunks` | 3.3 / 3.4 ms | 3.2 ns | 16.8 KiB |
| 16 MiB | `decrypt_chunks` | 54.3 / 58.8 ms | 3.2 ns | 16.8 KiB |
| 16 MiB | `encrypt_at_offset` (one shot) | 163.7 / 179.5 ms | 9.8 ns | 17.0 MiB (1.06 x output) |
| 16 MiB | `decrypt_at_offset` (one shot) | 85.6 / 90.2 ms | 5.1 ns | 17.0 MiB (1.06 x output) |

**Secure mode** (ChaCha20-Poly1305; scrypt N = 2^17, r = 8, p = 1). The scrypt work area (128 MiB) is inside OpenSSL and is not Python memory: process peak RSS rose from 79 MiB to 161 MiB on the first derivation.

| size | encrypt min / median | decrypt min / median | Python peak, encrypt | Python peak, decrypt |
|---|---|---|---|---|
| scrypt alone | 257.0 / 272.1 ms | - | 239 B | - |
| 16 B | 249.9 / 262.3 ms | 250.1 / 260.5 ms | 380 B | 1.0 KiB |
| 1 MiB | 243.6 / 246.4 ms | 248.1 / 255.2 ms | 2.0 MiB (2.00 x) | 1.0 MiB (1.00 x) |
| 64 MiB | 310.5 / 320.0 ms | 288.5 / 290.8 ms | 128.0 MiB (2.00 x) | 64.0 MiB (1.00 x) |

The cipher itself runs at about 1.5 GiB/s (64 MiB in 42 ms); nearly all the time is the deliberate key-derivation cost.

**Crack demo** (34-byte known plaintext, default search range [0, 131072)):

| true offset | candidates tried | min / median | peak memory |
|---|---|---|---|
| 1,024 | 1,025 | 63.6 / 65.4 ms | 41.7 KiB |
| 16,384 | 16,385 | 277.5 / 283.9 ms | 57.8 KiB |
| 65,536 | 65,537 | 1.83 / 1.84 s | 105.8 KiB |
| 131,071 (last candidate) | 131,072 | 4.98 / 5.22 s | 153.8 KiB |
| not in range (full search, clean failure) | 131,072 | 5.23 / 5.28 s | 153.8 KiB |

### GUI benchmarks

Measured with `python benchmarks/bench_gui_crack.py` and `python benchmarks/bench_gui_text.py` on the same i7-13620H, Windows 11, Python 3.13, full 2^17 range. The CPU was hot and clocked down during this run (the full-range miss took 7.43 s here against 5.23 s in the table above), so compare the ratios rather than the absolute times; numbers vary by machine.

| case | plain `crack.crack` | GUI `controller.run_crack` (progress and cancel) | ratio |
|---|---|---|---|
| offset not in range (full search) | 7.43 s | 7.55 s | 1.02x |
| hit at offset 131,071 | 7.73 s | 7.86 s | 1.02x |

- **Worst-case cancel latency** (Cancel at the start of the longest chunk, until the job reports cancelled): 1.35 to 1.71 s on the hot CPU, including the hand-off to the polling thread.
- **UI responsiveness during a crack**: lateness of a 50 ms UI tick, median 12.6 ms, max 14.2 ms (Windows timer granularity; no measurable starvation of the UI thread).
- **Large output**: a 2 MiB ciphertext, 4,194,304 hex characters, is wrapped, inserted and drawn in 30 to 42 ms. Before output wrapping, one 100,000-character line took 2.6 s and 1,000,000 characters did not finish in 5 minutes.

### CLI start-up

**CLI start-up** (whole process, min / median): `python -c pass` 22 / 26 ms; `encryptor --help` 51 / 63 ms; classic encrypt at a tiny offset 70 / 93 ms. `cryptography` is imported only for `--mode secure`.

## Known limitations and usage warnings

- **Classic mode is not secure.** See above. It is for learning only.
- **Quote passphrases that contain spaces.** With `--passphrase two words` and no input argument, argparse takes `two` as the passphrase and `words` as the text to encrypt, and standard input is ignored. Nothing can detect this. With an input argument as well, the command fails with exit code 2 (`unexpected extra arguments`, which are deliberately not echoed).
- **Prefer `--prompt`.** `--passphrase` puts the passphrase in shell history and process lists.
- **`--prompt` on Windows needs an interactive console.** `getpass` reads the console directly there, so with no interactive console (for example in a scheduled job or some IDE terminals) the command waits forever. This is a `getpass` limitation. Where `getpass` reports end of input instead, the command exits with code 2.
- **Piping in Windows PowerShell 5.1 can add a byte-order mark.** When `$OutputEncoding` is UTF-8 with a BOM, PowerShell prepends the BOM to whatever it pipes into a native command. `encrypt` then encrypts the BOM as part of the text, and `decrypt` rejects piped hex with `input is not ASCII text` (exit code 3). Pass the hex as an argument, or pipe from Git Bash, cmd or PowerShell 7.
- **Classic mode is for short messages.** Up to a few KiB is comfortable (4 KiB takes under a second at the worst offset on the benchmark machine, several times longer in a throttled process). Cost per block keeps growing with the position, so long inputs get progressively slower.
- **Classic decryption with a wrong passphrase** usually fails with `decrypted data is not valid UTF-8 (wrong passphrase or corrupted ciphertext)` and exit code 3, but it can also print wrong text with exit code 0, most likely for very short messages. The cipher has no integrity check, so the tool cannot tell.
- **Messages are text.** `encrypt` requires valid UTF-8, and classic `decrypt` requires the result to be valid UTF-8. `decrypt` prints the text followed by a newline.
- **Secure mode holds the whole message in memory** and needs 128 MiB for scrypt on every run. If that memory is not available the command fails with a clean error (exit code 1).
- **`crack` on very short messages.** For a known plaintext shorter than 4 bytes, the search may report an earlier offset that happens to encrypt that message identically.
- **GUI: one very long line of decrypted text is slow to display.** Tk's text layout is superlinear in the length of a single line. Encrypt output is wrapped at 64 characters for this reason (Copy still copies the unwrapped value), but decrypted plaintext is shown exactly as it is: a plaintext that is one line of hundreds of KB took 0.59 s to display at 400,000 characters and 17.7 s at 1,000,000. Ordinary text with line breaks is unaffected (100,000 characters in 0.14 s).
- **GUI: Cancel is not instant.** The crack checks for cancel once per digit chunk, so it stops within about 1 s (up to about 1.7 s measured on a throttled CPU).
- **GUI: Tkinter may be missing** on some Linux Python builds; install `python3-tk` (see [Install](#install)).
- Two optional speed-ups were measured but not applied: merging partial sums before each wide division in the BBP code (the full-range crack drops from about 5.0 s to 3.8 s) and a larger keystream block (14 to 20% faster above 2 KiB, at the cost of a bigger held key block).

## Project layout

```text
EncrypTOR/
  README.md
  pyproject.toml
  docs/
    DESIGN.md          design, interfaces, precision argument, trade-offs
  src/encryptor/
    __init__.py        exception hierarchy, Buffer alias
    cli.py             argparse front end
    pi_stream.py       BBP and the batched hex keystream
    classic.py         educational running-key cipher (not secure)
    secure.py          ChaCha20-Poly1305 with scrypt
    crack.py           known-plaintext offset recovery
    encoding.py        hex and decimal helpers
    gui/
      __main__.py      python -m encryptor.gui
      app.py           Tkinter widgets, shortcuts, polling (GUI entry point, run by bare `encryptor`)
      controller.py    display-free logic: validation, core calls, error mapping, worker jobs
      theme.py         dark ttk theme
  tests/               pytest suite (983 tests; GUI smoke tests skip without a display)
  benchmarks/          bench_pi_stream.py, bench_modes.py, bench_crack.py,
                       bench_crack_chunks.py, bench_gui_crack.py, bench_gui_text.py
```
