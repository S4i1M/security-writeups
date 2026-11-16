# sequences.py — evaluating a linear recurrence at 20 million terms

A write-up of a CTF challenge: the given code computes a 4th-order linear
recurrence naively and overflows the stack; the goal is to reach term
`20_000_000`, verify it against an MD5, and decrypt a flag.

**Flag:** `academy{b1g_numb3rs_56b2970a}`

---

## The challenge

```python
@functools.cache
def m_func(i):
    if i == 0: return 1
    if i == 1: return 2
    if i == 2: return 3
    if i == 3: return 4
    return 55692*m_func(i-4) - 9549*m_func(i-3) + 301*m_func(i-2) + 21*m_func(i-1)
```

with `ITERS = 2 * 10**7`. The result is taken modulo `10**10000`, hashed with
MD5 and compared to a known digest; if it matches, the digest's SHA-256 keys an
XOR over the encrypted flag.

So the task is: **compute `a(20_000_000) mod 10^10000`**, exactly.

## Why the given code dies

Two separate walls:

1. **Recursion depth.** `m_func(2e7)` nests 20 million calls deep. Python's
   default recursion limit is 1000, and even with the limit raised, the C stack
   overflows long before 20 million frames.
2. **Memory.** `@functools.cache` would memoise 20 million entries, each a
   ~10,000-digit integer. That is hundreds of gigabytes.

The comment in the source is honest about it: *"This will overflow the stack."*

## The maths: a linear recurrence is a matrix power

The recurrence has **constant coefficients** and is **linear**:

```
a(n) = 21·a(n-1) + 301·a(n-2) − 9549·a(n-3) + 55692·a(n-4)
```

That means the state vector `[a(n), a(n-1), a(n-2), a(n-3)]` advances by a fixed
linear map — a 4×4 matrix:

```
[a(n)  ]   [21  301  -9549  55692] [a(n-1)]
[a(n-1)] = [1    0     0      0  ] [a(n-2)]
[a(n-2)]   [0    1     0      0  ] [a(n-3)]
[a(n-3)]   [0    0     1      0  ] [a(n-4)]
```

So `a(n)` is the top entry of `M^(n-3) · [4, 3, 2, 1]`, and `M^k` is computed by
**binary exponentiation** in `O(log n)` matrix multiplications — about 25 of them
for `n = 2·10^7`.

Every operation is done modulo `10^10000`. That is valid because the recurrence
uses only addition and multiplication by constants: reducing modulo `m` at every
step gives the same answer as computing the full integer and reducing at the end
(the ring homomorphism `Z → Z/mZ` commutes with `+` and `×`).

## Approach 1 — matrix exponentiation

The straightforward version: keep a 4×4 matrix, square it while shifting the
exponent, and multiply it into the state vector on each set bit. That is 64
big-integer multiplications per matrix square, plus 16 per matrix–vector product.

This works and takes **~1.6 s** at `n = 2·10^7`.

## Approach 2 — Kitamasa (characteristic polynomial)

The matrix is a *companion* matrix, so there is a cheaper formulation. Its
characteristic polynomial is

```
P(x) = x^4 − 21x^3 − 301x^2 + 9549x − 55692
```

By Cayley–Hamilton, `P(M) = 0`, so `M^n` reduces to a degree-3 polynomial in
`M`. Equivalently, compute `x^n mod P(x)` by binary exponentiation on
**degree-3 polynomials** — 16 multiplications per product instead of 64 — and
then

```
a(n) = c0·a(0) + c1·a(1) + c2·a(2) + c3·a(3)
```

where `c0..c3` are the coefficients of `x^n mod P`. Reduction uses
`x^4 ≡ 21x^3 + 301x^2 − 9549x + 55692`.

This is the same algebra as the matrix version, with about a third of the
big-integer multiplications, and it runs in **~1.05 s** — roughly 35% faster.

## Why not diagonalisation?

Diagonalising `M` would give `a(n)` as `Σ wᵢ·λᵢⁿ`, but the eigenvalues `λᵢ` are
the roots of `P`, which are **irrational**. Over the reals that means floating
point, and we need the answer to 10,000 decimal digits — precision would be
destroyed. Kitamasa is the exact-arithmetic analogue: it does what
diagonalisation does (work with `x^n` modulo the characteristic polynomial)
without ever leaving the integers.

## Gotcha: Python's integer-to-string limit

Python 3.11 introduced a default cap of **4300 digits** on `int → str`
conversion, as an anti-DoS measure. Our solution has 10,000 digits, so

```python
str(sol)   # ValueError: Exceeds the limit (4300 digits) for integer string conversion
```

raises on modern Python. The fix is one line, before any conversion:

```python
sys.set_int_max_str_digits(0)   # 0 = no limit
```

Without it the code fails *after* the expensive part has already succeeded —
an easy hour to lose.

## Verification and decryption

The check is a chain, so correctness is verifiable at each step:

1. `sol % 10^10000` → decimal string `s`
2. `md5(s) == "96cc5f3b460732b442814fd33cf8537c"` → the number is right
3. `key = sha256(s)`; `flag = ENCRYPTED_FLAG XOR key` (byte-wise, key repeats
   only if needed — here the flag is shorter than the digest)

Because the MD5 gates everything, a wrong recurrence, a wrong modulus, or an
off-by-one in the exponent all fail loudly rather than silently producing
garbage. During development I checked `a(n)` against a direct dynamic-programming
loop for `n = 4..119` before trusting the fast path — which caught a real bug:
my first vector–matrix helper computed `Mᵀ·v` instead of `M·v`.

## Benchmarks

| Implementation | Time (`n = 2·10^7`) | Correct |
|---|---|---|
| given recursive code | — (stack overflow) | — |
| matrix exponentiation (4×4) | 1.60 s | ✅ |
| matrix, flat 16-element array | 1.53 s | ✅ |
| **Kitamasa (degree-3 polynomials)** | **1.05 s** | ✅ |

The bottleneck in all of them is big-integer multiplication of ~10,000-digit
numbers, so the win comes from *doing fewer of them*, not from micro-optimising
the loops.

## Takeaways

- **Constant-coefficient linear recurrences are matrix powers.** Whenever you see
  `a(n) = Σ cᵢ·a(n−i)`, think `O(log n)` binary exponentiation, not `O(n)` loops
  and never recursion.
- **Modular arithmetic commutes** with `+` and `×`, so you can reduce at every
  step and keep the numbers bounded — essential when the modulus is `10^10000`.
- **Companion matrices have a cheaper form.** Kitamasa is the polynomial version
  of the same idea and is meaningfully faster when the order is small.
- **Test the fast path against the slow one** on small inputs. That is what
  caught my transposed-matrix bug, and it is far cheaper than debugging a wrong
  MD5.
- **Know your runtime's limits.** Python's 4300-digit `int → str` cap is a
  modern trap that older write-ups predate.

## Files

- `solution.py` — the Kitamasa implementation, with verification and decryption.

```bash
$ time python3 solution.py
academy{b1g_numb3rs_56b2970a}

real    0m1.11s
```
