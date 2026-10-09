"""Conservative offline guessing estimates; never expose password structure."""

from dataclasses import dataclass
from collections.abc import Callable
from decimal import Decimal
from functools import lru_cache
from importlib.resources import files
import math
import re
import secrets
import string
import types
import unicodedata
from typing import TypeVar

from zxcvbn import matching, scoring

from . import crypto
from .errors import PasswordError, UsageError, WrongPassword
from .ui import UI

# Review each June and November TOP500 release. Peak bandwidth is an attacker
# ceiling, not a benchmark of a working Argon2 implementation.
ATTACKERS = {'June 2026': ('El Capitan', 44_544, 5.3e12)}
REFERENCE = 'June 2026'
FLOOR = 10**18
RECOMMENDED = 10**21
DUPLICATION = ('The local 7z key password must be different from the 7z password. If both layers '
               'share one password, cracking the 7z password opens the whole bundle, and anyone you '
               'give the 7z password to also has your local key password.')

_T = TypeVar('_T')


def retry(ui: UI, action: Callable[[], _T], *, new: bool = False) -> _T:
    """Retry correctable terminal entries; propagate cancellation and input failures."""
    while True:
        try:
            return action()
        except (PasswordError, WrongPassword) as exc:
            if not ui.can_retry_password(new=new):
                raise
            ui.warn(str(exc))
            ui.status('Try again, or press Ctrl-C to cancel (Command-C if your terminal maps it to interrupt).')


@lru_cache(maxsize=1)
def wordlist() -> tuple[str, ...]:
    words = tuple(line.split()[1] for line in
                  files('docvault').joinpath('data/eff_large_wordlist.txt').read_text().splitlines())
    if len(words) != 7776 or len(set(words)) != 7776:
        raise UsageError('The bundled EFF wordlist is damaged')
    return words


def text(password: bytes) -> str:
    try:
        value = password.decode('utf-8')
    except UnicodeError:
        raise PasswordError('Passwords must be UTF-8') from None
    if not value:
        raise PasswordError('An empty password is not allowed')
    if len(value) > 1024 or any(c in value for c in '\r\n\0'):
        raise PasswordError('Passwords must be at most 1024 characters without newlines or NUL bytes')
    return value


def pool(value: str) -> int:
    return (26 * any(c in string.ascii_lowercase for c in value)
            + 26 * any(c in string.ascii_uppercase for c in value)
            + 10 * any(c in string.digits for c in value)
            + 33 * any(c in string.punctuation + ' ' for c in value)
            + 100 * any(ord(c) > 127 for c in value)) or 100


def normalized(value: str) -> str:
    return unicodedata.normalize('NFKC', value).casefold()


def similar(first: bytes, second: bytes) -> bool:
    a, b = normalized(text(first)), normalized(text(second))
    if a in b or b in a:
        return True
    if abs(len(a) - len(b)) > 4:
        return False
    # Banded Levenshtein, bounded even for the maximum password length.
    prev = {i: i for i in range(min(len(b), 4) + 1)}
    for i, ca in enumerate(a, 1):
        row = {0: i} if i <= 4 else {}
        for j in range(max(1, i - 4), min(len(b), i + 4) + 1):
            row[j] = min(prev.get(j, 5) + 1, row.get(j - 1, 5) + 1,
                         prev.get(j - 1, 5) + (ca != b[j - 1]))
        if min(row.values(), default=5) > 4:
            return False
        prev = row
    return prev.get(len(b), 5) <= 4


def _pattern(value: str, other: str) -> float:
    value = value[:100]
    inputs = [other.lower(), *re.findall(r'[a-zA-Z]+', other.lower())] if other else []
    dictionaries = dict(matching.RANKED_DICTIONARIES,
                        user_inputs=matching.build_ranked_dict(inputs))
    matches = matching.omnimatch(value, dictionaries)
    # Use the pinned estimator's dynamic programming with a private globals
    # dictionary. No global monkeypatch or password retained in a cache.
    def brute(match):
        token = match['token']
        return pool(token) ** len(token) if len(token) >= 4 else scoring.bruteforce_guesses(match)

    namespace = dict(vars(scoring), bruteforce_guesses=brute)
    namespace['estimate_guesses'] = types.FunctionType(scoring.estimate_guesses.__code__, namespace)
    estimator = types.FunctionType(scoring.most_guessable_match_sequence.__code__, namespace,
                                   argdefs=scoring.most_guessable_match_sequence.__defaults__)
    return float(estimator(value, matches)['guesses'])


def _word_attack(value: str, other: str) -> float:
    eff = set(wordlist())
    other_words = re.findall(r'[a-zA-Z]{3,}', other.lower())
    ranks = [d for name, d in matching.RANKED_DICTIONARIES.items() if name != 'user_inputs']
    cost, listed = 1, 0
    symbols = set()
    for part in re.findall(r'[a-zA-Z]+|[0-9]+|[^a-zA-Z0-9]', value):
        lower = part.lower()
        if part.isascii() and part.isalpha():
            candidates = [26**len(part)]
            known = False
            if len(part) >= 3:
                if lower in eff:
                    candidates.append(7776)
                    known = True
                for rank in ranks:
                    if lower in rank:
                        candidates.append(rank[lower])
                        known = True
                if lower in other_words:
                    candidates.append(len(other_words))
                    known = True
            listed += known
            cost *= min(candidates)
        elif part.isascii() and part.isdigit():
            cost *= 10**len(part)
        elif part in string.punctuation + ' ':
            symbols.add(part)
        else:
            cost *= 128
    return float(cost * 33**max(0, len(symbols) - 1) / 2) if listed >= 2 else math.inf


def guesses(password: bytes, other: bytes = b'', *, generated: bool = False) -> float:
    value, known = text(password), text(other) if other else ''
    if generated:
        # Only call this for a freshly sampled six-word phrase, after typeback.
        return 7776**6 / 2
    return float(min(Decimal(pool(value))**len(value) / 2, _pattern(value, known),
                     _word_attack(value[:100], known)))


def speed(kdf: crypto.KdfParams) -> float:
    _, count, bandwidth = ATTACKERS[REFERENCE]
    return count * bandwidth / (kdf.memlimit * (3 * kdf.opslimit - 1))


def scientific(value: float) -> str:
    if value < 1000:
        return f'{value:.2g}'
    exponent = int(math.floor(math.log10(value)))
    return f'{value / 10**exponent:.2g} × 10^{exponent}'


def duration(seconds: float) -> str:
    def sig(value):
        return f'{float(f"{value:.2g}"):g}'

    if seconds < 60:
        return f'{sig(max(1, seconds))} second' + ('s' if seconds >= 1.5 else '')
    for unit, scale, bound in [('minutes', 60, 3600), ('hours', 3600, 86400),
                               ('days', 86400, 365.25 * 86400)]:
        if seconds < bound:
            return f'{sig(seconds / scale)} {unit}'
    years = seconds / (365.25 * 86400)
    for label, scale in [('trillion', 1e12), ('billion', 1e9), ('million', 1e6), ('thousand', 1e3)]:
        if scale <= years < scale * 1000:
            return f'{sig(years / scale)} {label} years'
    return f'{sig(years)} years' if years < 1000 else f'{scientific(years)} years'


@dataclass(frozen=True)
class Estimate:
    guesses: float
    speed: float

    @property
    def seconds(self):
        return self.guesses / self.speed


def estimate(password: bytes, kdf: crypto.KdfParams, other: bytes = b'', *, generated=False) -> Estimate:
    return Estimate(guesses(password, other, generated=generated), speed(kdf))


def report(ui: UI, label: str, password: bytes, kdf: crypto.KdfParams, other: bytes = b'',
           *, enforce=False, generated=False, local=False) -> Estimate:
    result = estimate(password, kdf, other, generated=generated)
    machine = ATTACKERS[REFERENCE][0]
    ui.status(f'{label}, pessimistic estimate:\n'
              f'  guesses needed   {scientific(result.guesses)} (weakest of three attacks)\n'
              f'  attacker speed   {scientific(result.speed)} per second ({machine}, TOP500 {REFERENCE})\n'
              f'  expected time    {duration(result.seconds)}')
    if enforce and result.guesses < FLOOR:
        advice = ('Change it with sudo docvault passwd first.' if local else
                  'Use six random words, 12 random characters from a password manager, or --generate-password.')
        raise PasswordError(f'The {label.lower()} is too weak: the minimum is 10^18 guesses '
                         f'(about {duration(FLOOR / result.speed)}). {advice} Nothing was changed.')
    if enforce and result.guesses < RECOMMENDED:
        ui.warn(f'Below the recommended 10^21 guesses (about {duration(RECOMMENDED / result.speed)}). '
                'Six random words or 12 random characters from a password manager reach it; see --generate-password.')
    return result


def whole(ui: UI, outer: Estimate, key: Estimate):
    ui.status(f'Whole bundle: {duration(outer.seconds)}, then {duration(key.seconds)}; '
              f'{duration(outer.seconds + key.seconds)} in total.')


def distinct(ui: UI, outer: bytes, local: bytes, outer_kdf: crypto.KdfParams):
    if similar(outer, local):
        time = duration(estimate(outer, outer_kdf).seconds)
        raise PasswordError('The local 7z key password matches the 7z password or is a close variant of it. '
                         'One cracked password would open both layers, so the bundle would last only the '
                         f'7z password\'s {time}, and anyone you give the 7z password to would also have '
                         'your local key password. Choose a different 7z password, or use '
                         'docvault bundle passwd for an existing bundle. Nothing was changed.')


def new_password(ui: UI, prompt: str, confirmation: str, *, generate=False) -> bytes:
    def choose():
        if generate:
            value = '-'.join(secrets.choice(wordlist()) for _ in range(6)).encode()
            ui.show_generated(value)
        else:
            value = ui.new_secret(prompt)
        text(value)
        if ui.new_secret(confirmation) != value:
            raise PasswordError('The passwords do not match; nothing was changed')
        return value

    return retry(ui, choose, new=True)
