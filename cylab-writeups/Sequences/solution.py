"""
sequences.py — solve the linear-recurrence challenge.

    a(0)=1, a(1)=2, a(2)=3, a(3)=4
    a(n) = 21*a(n-1) + 301*a(n-2) - 9549*a(n-3) + 55692*a(n-4)

We need a(2*10^7) mod 10^10000, then MD5-verify it and XOR-decrypt the flag.

The naive @cache recursion needs 20 million stack frames and a cache of 20
million huge integers, so it dies. The recurrence is linear with constant
coefficients, so it is a matrix power. Instead of a 4x4 matrix (64 big-int
multiplies per square), this uses the Kitamasa / polynomial method: compute
x^n modulo the characteristic polynomial

    P(x) = x^4 - 21x^3 - 301x^2 + 9549x - 55692

by binary exponentiation on degree-3 polynomials (16 multiplies per product),
then a(n) = sum(c_i * a(i)). That is the same algebra as diagonalisation, but
exact: the eigenvalues are irrational, so diagonalising over the reals would
lose the precision we need.
"""
import hashlib
import sys

MOD = 10**10000
N = 20_000_000
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex(
    "53c1beea6e427b3de1acf4834baed794f4bbd0dfe1d85f6a248ba4c12b"
)

INIT = (1, 2, 3, 4)
# x^4 = 21x^3 + 301x^2 - 9549x + 55692   (mod P), coefficients of x^0..x^3
RED = (55692, -9549, 301, 21)


def poly_mul(a, b):
    """Multiply two degree-3 polynomials modulo P, coefficients modulo MOD."""
    t = [0] * 7
    for i in range(4):
        ai = a[i]
        if ai:
            for j in range(4):
                t[i + j] = (t[i + j] + ai * b[j]) % MOD
    for k in (6, 5, 4):
        c = t[k]
        if c:
            t[k - 4] = (t[k - 4] + c * RED[0]) % MOD
            t[k - 3] = (t[k - 3] + c * RED[1]) % MOD
            t[k - 2] = (t[k - 2] + c * RED[2]) % MOD
            t[k - 1] = (t[k - 1] + c * RED[3]) % MOD
    return t[:4]


def a(n):
    """a(n) modulo MOD, computed as x^n mod P."""
    if n < 4:
        return INIT[n]
    result = [1, 0, 0, 0]   # the constant polynomial 1
    base = [0, 1, 0, 0]     # the polynomial x
    e = n
    while e:
        if e & 1:
            result = poly_mul(result, base)
        e >>= 1
        if e:
            base = poly_mul(base, base)
    return sum(result[i] * INIT[i] for i in range(4)) % MOD


def main():
    # Python 3.11+ refuses int->str above 4300 digits by default; we need 10000.
    sys.set_int_max_str_digits(0)

    sol = a(N)
    s = str(sol)

    if hashlib.md5(s.encode()).hexdigest() != VERIF_KEY:
        sys.exit("Incorrect solution")

    key = hashlib.sha256(s.encode()).digest()
    flag = bytes(c ^ key[i] for i, c in enumerate(ENCRYPTED_FLAG)).decode()
    print(flag)


if __name__ == "__main__":
    main()
