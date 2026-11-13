# EncrypTOR design

This document describes how EncrypTOR is built and why. It covers the module layout, the public interfaces, the pi-digit (BBP) keystream and its precision argument, the secure-mode format, the CLI contract, the desktop GUI, the test strategy and the main trade-offs. Usage and benchmark numbers are in the README.

Classic mode is an educational cipher and is NOT secure. Secure mode is the one for real data.

## 1. Goals and non-goals

Goals:

- A command-line toolkit with three commands: `encrypt` and `decrypt` in two modes, and `crack`.
- `classic`: a running-key cipher whose keystream is the hex digits of pi (computed with the BBP formula) starting at a secret offset derived from a passphrase. It exists to show how such a cipher works and how it breaks.
- `secure`: authenticated encryption with ChaCha20-Poly1305 and an scrypt-derived key, built only from the `cryptography` library.
- `crack`: recover the classic offset from a known plaintext/ciphertext pair.
- A desktop GUI (Tkinter, standard library) over the same functions, with a cancellable crack demo (section 9).
- Runtime dependencies: the standard library and `cryptography`. Python 3.11 or later, full type hints, `mypy --strict` clean.
- Low runtime and memory use: stream where the design allows it, avoid copies, use `argparse`, import heavy modules lazily.

Non-goals:

- No custom cryptography in secure mode: no hand-written cipher, MAC, key derivation or comparison.
- No attempt to make classic mode secure. Its weaknesses are the point of the `crack` command.
- Secure mode is not streaming (see section 12).

## 2. Module layout

```text
src/encryptor/
  __init__.py    exception hierarchy, Buffer alias
  encoding.py    hex and decimal text helpers
  pi_stream.py   BBP hex digits and the batched keystream
  classic.py     offset derivation and the chained XOR cipher
  secure.py      ChaCha20-Poly1305 with scrypt
  crack.py       known-plaintext offset recovery
  cli.py         argparse front end; with no arguments it opens the GUI
  gui/
    __init__.py    docstring only, so importing the package never loads tkinter
    __main__.py    python -m encryptor.gui
    controller.py  display-free logic: validation, core calls, error mapping, worker jobs
    app.py         Tkinter + ttk widgets, shortcuts, polling
    theme.py       dark ttk theme
```

Dependencies (no cycles):

```text
__init__   <- every module
encoding   -> __init__
pi_stream  -> __init__
classic    -> pi_stream
secure     -> cryptography
crack      -> pi_stream, classic
cli        -> encoding; imports classic, crack, secure, getpass and gui.app lazily, only in the command that needs them
gui.controller -> encoding, classic, secure, crack (never tkinter)
gui.app        -> gui.controller, gui.theme, tkinter
```

Conventions:

- `Buffer = bytes | bytearray | memoryview`.
- Module constants are read at call time, never bound as default argument values, so tests can monkeypatch them.
- Every core function's docstring states its time and space complexity.
- Only `cli.py` prints (the GUI shows results in its window and prints one line, "no display available", when Tk cannot start). Passphrases, keys and derived offsets never appear in output or exception messages. The one exception is `crack`, which prints the offset it recovers.
- Programmer errors (negative offset, odd digit count) raise the built-in `ValueError`. Anything a user can trigger raises a subclass of `EncryptorError`.

### Exception hierarchy

Defined in `__init__.py`, which imports no submodule, so there are no import cycles.

```text
EncryptorError                      base; the CLI reports it as one line
  InputFormatError                  bad hex/decimal text, invalid UTF-8, unusable crack inputs
  MalformedCiphertextError          secure blob is structurally wrong
    TruncatedCiphertextError        blob shorter than the minimum
    UnsupportedVersionError         unknown version byte
  AuthenticationError               secure: wrong passphrase, or corrupted or tampered data
  OffsetNotFoundError               crack: no offset in range (candidates_tried, elapsed_seconds)
  CrackStoppedError                 crack: the progress callback stopped the search (candidates_tried, elapsed_seconds)
  PrecisionError                    BBP guard could not be satisfied (practically unreachable)
```

## 3. The pi keystream (`pi_stream.py`)

### Indexing

`position` counts hex digits after the point, 0-based. Position 0 is the `2` in `3.243F6A88...`. Key byte `i` at offset `o` is `16 * digit[o + 2i] + digit[o + 2i + 1]` (two hex digits per byte, high nibble first), so offset 0 gives `24 3F 6A 88 ...`. Odd offsets are valid.

### Public interface

```python
HEX_DIGITS_PER_BATCH = 8       # default count of pi_hex_int
GUARD_BITS = 64                # extra fractional bits below the returned digits
MAX_GUARD_BITS = 1024          # fallback ceiling
KEYSTREAM_BLOCK_DIGITS = 4096  # digits per BBP evaluation in the keystream (even)

def pi_hex_int(position: int, count: int = 8, *, guard_bits: int | None = None) -> int
def pi_hex_digits(position: int, count: int) -> str      # uppercase, zero padded
def pi_hex_digit(position: int) -> int                    # separate single-digit reference path
def keystream_blocks(offset: int, length: int | None = None, *, block_digits: int | None = None) -> Iterator[bytes]
def keystream(offset: int) -> Iterator[int]
```

- `pi_hex_int` returns the `count` digits at `[position, position + count)` as one integer, from one BBP evaluation. `ValueError` for a negative position or a non-positive count or guard; `PrecisionError` if the guard still fails at `MAX_GUARD_BITS`.
- `pi_hex_digit` is deliberately a separate, plain per-term loop that shares no code with the batched path, so comparing the two is a real test rather than a tautology.
- `keystream_blocks` yields key bytes in blocks of at most `block_digits / 2` bytes. With `length` it yields exactly that many bytes and never asks for more digits than needed, so short messages pay for narrow arithmetic only. Arguments are validated when it is called, not on first iteration.
- The concatenated output does not depend on `block_digits`.

### BBP in integer fixed point

The formula is

```text
pi = sum over k >= 0 of 16^-k * ( 4/(8k+1) - 2/(8k+4) - 1/(8k+5) - 1/(8k+6) )
```

The digits from position `d` onward are the digits of `frac(16^d * pi)`. For a request of `c` digits with guard `G` bits, the sum is carried with `P = 4c + G` fractional bits as a Python integer.

Why integers and not floats: a double has 53 mantissa bits, the summation error grows with `d`, and there is no usable error bound. Python integers give a provable bound at any width.

The four parts of term `k` combine into one positive fraction `n(k) / m(k)` with

```text
n = 120k^2 + 151k + 47
m = 512k^4 + 1024k^3 + 712k^2 + 194k + 15
```

Terms are processed in groups of `_GROUP_TERMS = 8` consecutive `k`. A group is merged into one exact fraction `num/den` (`num = (num << 4) * m + n * den`, `den *= m`). Then:

- Head group (`hi <= position`, the terms where the 16-power is positive): the contribution is `frac(16^(position - hi) * num / den)`, computed as `(pow(16, position - hi, den) * num % den) << P) // den`. One modular exponentiation and one wide division per group.
- Tail group (`hi > position`): a plain shifted quotient, `(num << (P + 4 * (position - hi))) // den`. The loop stops once the shift would reach zero, and the dropped remainder is below one unit in the last place.
- A group never straddles `position`.

### Precision argument

- Each group is floored once, so the computed sum `S` is never above the true value `X`, and is below it by less than the number of groups plus one. The code uses the deliberately loose bound `E = 8 * (d + P)`, which is always larger.
- The batch is accepted only if its low `G` bits `g` satisfy `E <= g < 2^G - E`. Then `S` and `X` lie in the same `2^G` bucket, so no carry or borrow can reach the returned digits. This also covers wrap-around modulo `2^P`.
- With `G = 64` and `d < 2^18`, `E < 2^22`, so a batch is rejected with probability about `2^-41`.
- Fallback: on rejection, `G` is doubled and the whole batch is recomputed (64, 128, ... up to `MAX_GUARD_BITS`), then `PrecisionError`. A rejection needs a run of about `G / 4` consecutive `0` or `F` digits right after the batch, so one doubling practically always resolves it. The `guard_bits` parameter exists so tests can force this path.

### Cost model

An evaluation is dominated by about `4(d + 1)` modular exponentiations, so its cost is roughly `O(d log d)` regardless of whether 1 or 8 digits are requested. That is why digits are computed in batches (8 per call as the tested primitive, up to 4096 per call in the keystream): the position cost is paid once per batch.

There is no cheap "next digits" step in BBP. Generating `n` key bytes starting at offset `o` costs `ceil(2n / block_digits)` evaluations, each at a growing position. The consequence is stated plainly in section 12: classic mode is not literally "O(n) after the initial offset cost".

## 4. Classic mode (`classic.py`)

Not secure; for learning only.

```python
OFFSET_BOUND = 1 << 17     # offsets are in [0, 2**17)
CHAIN_IV = 0xA5            # c[-1]

def derive_offset(passphrase: str) -> int
def encrypt_at_offset(plaintext: Buffer, offset: int) -> bytes
def decrypt_at_offset(ciphertext: Buffer, offset: int) -> bytes
def encrypt(plaintext: Buffer, passphrase: str) -> bytes
def decrypt(ciphertext: Buffer, passphrase: str) -> bytes
def encrypt_chunks(chunks: Iterable[Buffer], offset: int) -> Iterator[bytes]
def decrypt_chunks(chunks: Iterable[Buffer], offset: int) -> Iterator[bytes]
```

- `derive_offset` is `int.from_bytes(sha256(passphrase.encode("utf-8")).digest(), "big") % OFFSET_BOUND`.
- Cipher: `c[i] = p[i] XOR k[i] XOR c[i-1]` with `c[-1] = CHAIN_IV`; decryption is `p[i] = c[i] XOR k[i] XOR c[i-1]`. The chaining stops repeated plaintext bytes from producing a repeating ciphertext pattern. It adds no secrecy.
- Output length equals input length. Empty in, empty out. A wrong passphrase is undetectable at this level: `decrypt` returns different bytes, never an error.
- The cipher layer works per keystream block with big-integer XORs. Decryption is `c ^ k ^ (prev || c[:-1])`. Encryption is a prefix XOR computed by log-step doubling, so there is no per-byte Python loop.
- The chunk API (`encrypt_chunks`, `decrypt_chunks`) carries one chain byte and at most one key block between chunks: O(1) extra memory. Joining its output equals the one-shot result for any split of the input.
- The one-shot functions collect output through `io.BytesIO` and `getvalue()`, which keeps peak memory near the output size plus a small margin rather than twice the output.
- `OFFSET_BOUND` is a usability limit, not a security parameter. The cost of one evaluation grows with the position, so a larger bound slows every command, while the cost of the crack search grows with about the square of the bound. The measured justification is in the comment above the constant.

## 5. Secure mode (`secure.py`)

Uses only `ChaCha20Poly1305`, `Scrypt` and `InvalidTag` from `cryptography`, plus `os.urandom`.

```python
VERSION = 1
SALT_LEN = 16; NONCE_LEN = 12; TAG_LEN = 16; KEY_LEN = 32
HEADER_LEN = 1 + SALT_LEN + NONCE_LEN      # 29
MIN_BLOB_LEN = HEADER_LEN + TAG_LEN        # 45
SCRYPT_N = 1 << 17; SCRYPT_R = 8; SCRYPT_P = 1

def encrypt(plaintext: Buffer, passphrase: str) -> bytes
def decrypt(blob: Buffer, passphrase: str) -> bytes
```

Format: `version (1) || salt (16) || nonce (12) || ciphertext || tag (16)`, output as hex by the CLI.

- Key: `Scrypt(salt, 32, N, r, p).derive(passphrase.encode("utf-8"))`. At `N = 2^17, r = 8, p = 1` this needs 128 MiB and takes a fraction of a second. The memory cost is the security property, and it is paid by an attacker on every guess. These parameters match the first scrypt configuration in the OWASP Password Storage Cheat Sheet; that guidance is written for password storage, and here the same parameters are used to derive an encryption key.
- A fresh salt and nonce come from `os.urandom` on every call. The salt gives each message its own key, so a nonce is never reused under one key, and encrypting the same input twice gives different output.
- The 29-byte header (version, salt, nonce) is passed as associated data, so changing any header byte fails authentication.
- `decrypt` checks, in order: empty input (`TruncatedCiphertextError`), version byte (`UnsupportedVersionError`), minimum length (`TruncatedCiphertextError`), then derives the key and decrypts. `InvalidTag` becomes `AuthenticationError` (raised `from None`). A wrong passphrase and any tampering give the same error, and unauthenticated plaintext is never returned.
- A scrypt `MemoryError` is re-raised as a plain `EncryptorError` without the original message, which the CLI reports with exit code 1.
- The AEAD is one-shot, so the whole message is in memory (see section 12).

## 6. Crack (`crack.py`)

```python
CRACK_PREFIX_BYTES = 4       # 8 hex digits; a wrong offset survives with probability 2^-32
CRACK_CHUNK_DIGITS = 16384   # digits generated per BBP evaluation while building the table
CRACK_PROGRESS_CHUNK_DIGITS = 12288   # chunk size when a progress callback is given

ProgressCallback = Callable[[int, int], bool]   # progress(tried, total) -> keep going?

@dataclass(frozen=True, slots=True)
class CrackResult:
    offset: int
    candidates_tried: int
    elapsed_seconds: float

def crack(plaintext: Buffer, ciphertext: Buffer, max_offset: int | None = None,
          *, progress: ProgressCallback | None = None) -> CrackResult
```

Strategy:

1. A known pair reveals the keystream with no pi work: `k[i] = p[i] XOR c[i] XOR c[i-1]` (with `c[-1] = CHAIN_IV`). Write it as uppercase hex digits: the full needle and a prefix needle of the first `2 * min(m, 4)` digits.
2. Generate the pi hex digits of the search range once, in increasing position, `CRACK_CHUNK_DIGITS` per evaluation, into one `bytearray`. Candidate offsets are consecutive positions in that table, so nothing is recomputed per candidate.
3. After each chunk, slide the prefix over the new digits with `bytearray.find` (C speed), resuming `len(prefix) - 1` digits before the previous end. On a prefix hit, compare the full needle, extending the table if needed. Accept only on a full match, and stop at the first one so later chunks are never generated.

The first few ciphertext bytes reject almost every wrong offset, so the full message is never decrypted per candidate.

- `max_offset` defaults to `OFFSET_BOUND`, read at call time. Offsets `0 .. max_offset - 1` are searched in increasing order. The result reports `candidates_tried = offset + 1`.
- Errors: `InputFormatError` for empty or unequal-length inputs; `ValueError` if `max_offset < 1`; `OffsetNotFoundError` (with `candidates_tried = max_offset` and the elapsed time) if nothing matches.
- A known plaintext shorter than 4 bytes is searched with the whole message as the prefix and may match an earlier coincidental offset.
- Time is dominated by generating the table: about `O(D^2 / w)` for `D` digits, because each chunk is evaluated at a growing position. Memory is one byte per digit generated.

The chunk size trades low-offset latency against total time. A hit at a small offset only pays for the first chunk; larger chunks make full-range searches slightly faster but small hits several times slower, so 16384 is a compromise.

### Progress and stopping

`progress` is optional and keyword-only. It exists so a caller (the GUI) can show progress and cancel a search; the CLI does not pass it, and with `None` the search is exactly the callback-free one.

- It is called as `progress(tried, total)` before the first chunk, after each chunk with no match, and before each extension of the table while a prefix hit is being verified. Offsets `0 .. tried - 1` are ruled out; `tried` never decreases and stays below `total`.
- Returning `False` stops the search: no further digits are generated and `crack` raises `CrackStoppedError` with `candidates_tried = tried`. It is deliberately not an `OffsetNotFoundError`, because offsets from `tried` upward were never examined.
- With a callback, the table grows in `CRACK_PROGRESS_CHUNK_DIGITS` chunks, so a stop takes effect within one chunk. Smaller chunks cancel faster but repeat more work, because every chunk pays for its position again. Measured over the full range, 8192 digits cost 1.10 to 1.15 times the callback-free search and 12288 costs 1.00 to 1.01 times, with the longest chunk taking about 0.9 s (up to about 1.7 s on a throttled CPU). 12288 is the smallest width with no measurable overhead.

An earlier approach searched in growing stages (`max_offset` = 8192, 32768, ... up to the full range) and checked for cancel between stages, with no change to `crack`. It was rejected: `crack` always starts at offset 0, so the last stage is a full search that cannot be interrupted (worst-case cancel about 12 s), the progress bar jumped from about 25% to 100%, and repeating the earlier stages cost 1.3 to 1.7 times the plain search.

## 7. Encoding helpers (`encoding.py`)

```python
def encode_hex(data: Buffer) -> str        # lowercase, no separators
def decode_hex(text: str) -> bytes         # strips surrounding whitespace, case-insensitive
def encode_decimal(data: Buffer) -> str    # "72 105 0"
def decode_decimal(text: str) -> bytes     # whitespace separated, each token 0..255
```

`decode_hex` rejects non-hex characters, odd length and whitespace between pairs. `decode_decimal` accepts ASCII digits only (no sign, underscore, `0x` prefix or non-ASCII digits) with values 0 to 255. Both raise `InputFormatError`, and messages never echo the input.

## 8. CLI (`cli.py`)

```text
encryptor encrypt --mode {classic,secure} [--decimal] (--passphrase P | --prompt) [TEXT | -]
encryptor decrypt --mode {classic,secure} [--decimal] (--passphrase P | --prompt) [HEX | -]
encryptor crack   [--max-offset N] --plaintext TEXT --ciphertext HEX
```

`main(argv=None) -> int` returns an exit code and does not raise for expected failures, so tests call it directly.

With no arguments at all, `main` opens the GUI and returns its exit code instead of printing a usage error. `encryptor.gui.app` is imported only in that case, so the CLI commands never load tkinter and start-up stays short. Any argument, including `--help`, runs the CLI as before. Because `encryptor` is a console script, launching it from a Windows shortcut also opens a console window; from a terminal it uses that terminal.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (also `--help`) |
| 1 | Any other error (for example no memory for scrypt), or stdout is a closed pipe |
| 2 | Usage error: missing or conflicting options, empty passphrase, `--decimal` with secure, extra arguments, invalid `--max-offset`, `--prompt` with no terminal |
| 3 | Bad input: invalid hex or decimal, invalid UTF-8, truncated secure data or unknown version, classic decryption that is not valid UTF-8, bad `crack` inputs |
| 4 | Authentication failed (wrong passphrase, or corrupted or tampered data) |
| 5 | `crack`: no offset in range |
| 130 | Interrupted (Ctrl-C) |

### Streams

- Results go to stdout: hex (or decimal) plus a newline for `encrypt`, the text plus a newline for `decrypt` (written through `sys.stdout.buffer`), three lines for `crack`.
- The classic-mode warning ("classic mode is an educational cipher and is NOT secure"), error lines and usage errors go to stderr, so stdout stays pipeable.
- `sys.stdin`, `sys.stdout` and `sys.stderr` are looked up at call time so tests can substitute them.

### Input handling

- The positional argument, or standard input when it is `-` or omitted. On `encrypt`, stdin is taken exactly (no newline stripping) and must be valid UTF-8. On `decrypt`, stdin is ASCII and surrounding whitespace is stripped.
- `--prompt` reads the passphrase with `getpass.getpass`, looked up at call time.
- Classic decryption checks that the result is valid UTF-8 and fails with exit 3 otherwise. A wrong classic passphrase therefore usually fails, but can occasionally print wrong text, because the cipher has no integrity check.

### Hardening

- Unrecognized extra arguments are not echoed (`parse_known_args`, then a fixed usage error), because they may be the tail of an unquoted multi-word passphrase.
- A closed stdout (`BrokenPipeError`, or `OSError` with `EINVAL` on Windows) exits 1 with no traceback. Output is flushed inside `main` so the error is caught there.
- Writes to stderr are best-effort through one helper: a broken stderr never changes the exit code, and its descriptor is pointed at the null device so the interpreter's exit flush cannot override the code.
- `--max-offset` accepts ASCII digits only, at least 1, and the rejected value is not echoed.
- Ctrl-C prints one line and exits 130. `EOFError` from `getpass` is a usage error.
- Imports of `classic`, `crack`, `secure` and `getpass` are deferred, so `--help` and classic mode never import `cryptography`.

## 9. GUI (`gui/`)

A desktop front end in Tkinter + ttk (standard library, no new dependency). It is started by `encryptor` with no arguments or by `python -m encryptor.gui`, and has two tabs: Encrypt/Decrypt and the crack demo.

### Design rules

- **Thin layer.** The GUI calls `classic`, `secure`, `crack` and `encoding` directly, in the same process. It contains no cryptography and never runs the CLI as a subprocess.
- **Logic separate from widgets.** `controller.py` holds every decision in plain functions and small frozen dataclasses and never imports tkinter, so it is unit-tested without a display. `app.py` only builds widgets, turns their contents into requests, starts jobs and shows results.
- **Never block the UI thread.** scrypt (about a quarter of a second and 128 MiB) and the crack search (seconds) run on a worker thread.

### Controller interface

```python
@dataclass(frozen=True, slots=True)
class CipherRequest:          # passphrase excluded from repr
    action: Literal["encrypt", "decrypt"]
    mode: Literal["classic", "secure"]
    text: str
    passphrase: str
    decimal: bool = False

@dataclass(frozen=True, slots=True)
class CrackRequest:
    plaintext: str
    ciphertext_hex: str
    max_offset: int | None

def prepare_cipher(request: CipherRequest) -> bytes     # cheap validation and decoding only
def run_cipher(request: CipherRequest) -> str           # prepare + core call
def parse_max_offset(text: str) -> int | None           # ASCII digits, 1 .. OFFSET_BOUND
def run_crack(request: CrackRequest, *, cancel: threading.Event,
              progress: Callable[[CrackProgress], None] | None = None) -> CrackResult
def describe_error(error: BaseException) -> ErrorInfo   # friendly title and message
def wrap_lines(text: str, width: int = 64) -> str

class Job(Generic[T]):        # one daemon thread, one SimpleQueue, one cancel Event
    def poll(self) -> list[Progress | Done[T] | Failed]
    def cancel(self) -> None
    running: bool

def start_cipher(request: CipherRequest, payload: bytes | None = None) -> Job[str]
def start_crack(request: CrackRequest) -> Job[CrackResult]
```

### Threading

- A `Job` starts one daemon thread. The worker never touches tkinter: it only puts events on a `queue.SimpleQueue` and reads a `threading.Event` for cancel. It always ends with exactly one `Done` or `Failed`.
- The UI drains events with `root.after` polling every 50 ms (`POLL_INTERVAL_MS`), only while a job is running. All widget updates happen on the main thread.
- Only one job runs at a time; both Run buttons are disabled while one is busy.
- The poll loop is robust: if applying an event raises, both jobs are abandoned, the UI returns to idle and the error is shown as a dialog. After the window closes, a closed flag stops every callback from touching destroyed widgets.
- Clear on the Encrypt/Decrypt tab drops a running cipher job and discards its result. scrypt cannot be interrupted, so the dropped worker keeps running until it finishes; Run refuses to start a new cipher job until then ("Previous operation still finishing..."), so repeated Run and Clear cannot pile up 128 MiB workers.

### Crack: cancel and progress

`run_crack` makes one `crack.crack` call with a `progress` callback (section 6). The callback runs on the worker thread: it returns `False` once the cancel event is set, and otherwise puts a `CrackProgress` event on the queue. The bar shows `(tried / total) ** 2`, because generating digits up to position d costs about O(d^2), so the bar moves roughly evenly in time.

A cancel seen at any point, including after the core has already finished, ends as `CrackCancelledError` (shown as "Cancelled" in the status line), never as "Offset not found". `Failed` carries explicit `cancelled` and `not_found` flags, so the UI never inspects message text.

### Passphrase handling

- The entry is masked (`show="*"`) with a Show toggle. Show is reset to masked at the start of every run, on Clear, and when a crack starts.
- The entry has `exportselection=False`, and `<<Copy>>` and `<<Cut>>` are blocked on it, so the passphrase cannot reach the clipboard or the X11 selection.
- `prepare_cipher` runs on the UI thread before the job starts. If the input is invalid, a dialog is shown and the passphrase stays in the field. Otherwise the field is cleared as the job starts, unless "Keep passphrase" is checked.
- The passphrase is never logged, printed, written to disk or included in an error message. `CipherRequest` hides it from `repr`, and the worker drops its reference to the request when the work ends.
- Python strings and Tk's own buffer cannot be zeroed, so the passphrase may remain in process memory until it is garbage-collected. This is the same limit as the CLI.

### Output and input text

- Tk draws one very long line extremely slowly (about 2.6 s for 50 KB, minutes for 500 KB). Encrypt output is therefore displayed wrapped at 64 characters (`wrap_lines`; decimal output is broken only at spaces). Copy copies the unwrapped value, and Swap moves the displayed text into the input.
- Decrypt and crack input remove ASCII whitespace (space, tab, CR, LF, VT, FF) before hex decoding, so wrapped or pasted hex works. Non-ASCII whitespace inside the hex is rejected as invalid.
- Decrypted plaintext is shown exactly as produced, never wrapped, because wrapping would change it. A plaintext that is one very long line is therefore still slow to display (section 13).
- The output and result widgets keep no undo history, and every programmatic change to an input widget resets its undo stack, so Ctrl+Z cannot bring back cleared text.

### Errors

Every exception is mapped by `describe_error` to a fixed title and message. `EncryptorError` subclasses get specific wording (for example a wrong passphrase or tampered data in secure mode); anything else shows only the exception type name. Messages never repeat the input or the passphrase. Tk callback errors go through `report_callback_exception`, so the user never sees a traceback.

### Window

- Dark theme from one palette on ttk's `clam` theme, so it looks the same on Windows, macOS and Linux.
- Minimum size 720 x 540. Ctrl+Enter runs and Ctrl+L clears (Cmd also works on macOS). The run keys are bound on each text widget and return "break", so Ctrl+Enter never inserts a newline into the text being encrypted.
- Classic mode shows a persistent "Educational, not secure" banner; the crack tab always shows it.

## 10. Testing strategy

- Round trips in both modes: empty input, one character, long text, emoji and other non-ASCII UTF-8.
- BBP correctness against a 64-digit golden vector (`243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89`) at offset 0 and at several even and odd offsets, plus an independent reference: Machin's formula `16*atan(1/5) - 4*atan(1/239)` in integer fixed point, which shares nothing with BBP, compared at far positions and over a whole wide batch.
- Batched output equals digit-by-digit output from `pi_hex_digit`, including across group boundaries and with the guard fallback forced through a tiny `guard_bits`.
- Chaining: repeated plaintext bytes do not give a repeating ciphertext, checked against a recurrence written out in the test.
- Secure mode: two encryptions of one input differ; a wrong passphrase raises `AuthenticationError`; flipping every single bit of a ciphertext in turn is rejected (the version byte as an unsupported version, every other bit as an authentication failure); structural errors give the right exception.
- Crack recovers the offset for known pairs, reports a clean failure when the offset is out of range, and gives the same result for any chunk size.
- CLI: argument and stdin input, `--decimal`, bad input, missing passphrase, exit codes, that classic output carries the warning and secure output does not, that no secret appears in output, extra-argument echo, `getpass` failures, Ctrl-C, closed stdout and stderr pipes (with fakes, and with real pipes in subprocesses).
- Crack progress: the callback is monotonic, returning `False` raises `CrackStoppedError` (also while a prefix hit is being extended), and `progress=None` is unchanged.
- GUI controller, without a display: round trips, input validation, error mapping, cancel at any point, output wrapping and whitespace-tolerant decoding.
- GUI window, skipped when no display is available: builds the real window and drives it (shortcuts, passphrase masking and clearing, clipboard and selection rules, Clear during a job, poll recovery, closing the window).
- Speed without weakening production: tests that exercise the CLI or passphrase-level classic mode monkeypatch `secure.SCRYPT_N` and `classic.OFFSET_BOUND` to small values. That only changes a parameter passed to the library, no cryptography is reimplemented. One test asserts the production constants and does a real round trip.

## 11. Performance notes

Measured numbers are in the README. The design points behind them:

- The keystream dominates classic mode. Computing 8 digits costs the same as computing 1, so the keystream asks for up to 4096 digits (2 KiB of key) per evaluation and never more than the message needs.
- Grouping terms (section 3) cut the wide divisions, the main cost after the modular exponentiations, and made wider blocks pay off. Output is bit-identical to the per-term version.
- The cipher layer is O(n) time with O(1) extra memory through the chunk API, and the one-shot API holds the output plus a small margin.
- Secure mode costs the fixed scrypt derivation plus about 1 ms per MiB. Encryption holds about twice the message in Python memory (one header-plus-ciphertext copy), decryption about once, plus scrypt's 128 MiB work area inside OpenSSL.

## 12. Decisions and trade-offs

- **Integer fixed-point BBP with a proven guard**, not floats, so a wrong digit cannot silently corrupt the keystream.
- **Classic keystream is not literally O(n) after the offset cost.** BBP pays for the position on every evaluation. The design keeps the 8-digit batch as the tested primitive, uses 4096-digit blocks in the keystream, and documents the real complexity. The strict alternative (`KEYSTREAM_BLOCK_DIGITS = 8`) gives identical output but is far slower at high offsets. Classic mode is practical for short messages, a few KiB.
- **Crack default range is the full `OFFSET_BOUND`**, so any passphrase-derived offset is found. A smaller default would be faster but would miss most passphrases. The search time is the evidence that classic mode is not secure.
- **Secure mode is one-shot.** `ChaCha20Poly1305` is a one-shot AEAD and the format has a single tag, so the message is held in memory. Chunked framing would be a different format and is out of scope.
- **scrypt at `N = 2^17`** (128 MiB). The memory cost is the point. A lower setting (`N = 2^15`, 32 MiB) would be quicker but weaker.
- **A wrong classic passphrase is not detected** by the cipher. Adding a check value would be a feature outside the scope of an educational cipher.
- **Exceptions live in `__init__.py`**, so the layout stays at one file per concern and there are no import cycles.
- **Text only.** `encrypt` requires valid UTF-8 and classic `decrypt` requires UTF-8 output; stdin is not newline-stripped on `encrypt`.

## 13. Known limits and open options

- In the GUI, a decrypted plaintext that is a single very long line (hundreds of KB) is slow to display, because Tk is slow with long lines and the plaintext cannot be wrapped without changing it.
- Crack cancel in the GUI takes effect within one progress chunk: about 1 s, up to about 1.7 s on a throttled CPU.
- The GUI has been tested on Windows only.

- Quote a passphrase that contains spaces. Unquoted, `--passphrase two words` makes argparse take the second word as the text and ignore stdin. The grammar cannot detect this.
- On Windows, `--prompt` reads the console directly and waits forever without an interactive console; this is a `getpass` limitation.
- In Windows PowerShell 5.1 with UTF-8-with-BOM output, piped input arrives with a byte-order mark, so piped `decrypt` fails cleanly (exit 3) and piped `encrypt` includes the mark in the text.
- Two speed-ups were measured and not applied. Merging partial sums before each wide division in `_bbp_sum` takes the full-range crack from about 5.0 s to 3.8 s but adds complexity to the precision-critical code. A keystream block of 8192 digits is 14 to 20% faster above 2 KiB but doubles the held key block.
- The tool has had no external audit.
