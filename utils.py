
"""A utility library I'm putting together for CS456 Cryptography.

Contains functions that have been found to be useful across multiple assignments."""

import math
import random

###############################
# PRIME NUMBER THEORY FUNCTIONS
###############################


def rab_exp_mod(b: int, e: int, m: int) -> int:
    """A version of exp_mod that will incorporate the rabin algorithm.
    NOT a replacement for exp_mod, since it will try to return 0 for composite numbers.
    Based on the right-to-left binary method."""
    c = 1
    while e > 0:
        if e & 1:
            c = (c * b) % m
        e = e >> 1
        z = (b * b) % m
        # rabin algorithm
        if (z == 1) and (b != 1) and (b != m - 1):
            return 0
        else:
            b = z
    return c


def gen_n(k: int) -> int:
    """Generate a k-bit odd number for a given value of k."""
    rand = 0
    # ensures that the first and last bit of the integer is always high
    while not rand & 1 or rand % 5 == 0:
        rand = random.randint(2 ** (k - 1) + 1, 2 ** k - 1)
    return rand


def is_prime(m: int, k: int) -> bool:
    """Implements the Miller-Rabin algorithm to check if a given number is prime.
    Runs the algorithm k times to ensure accuracy of 1-(1/(2**k))"""
    for i in range(k):
        a = random.randint(1, m - 1)
        if rab_exp_mod(a, m, m) != a:
            return False
    return True


def gen_safe_prime(k: int) -> int:
    """Generate a (k-1)-bit prime q and confirm that that 2q+1 results in a safe prime.
    Returns the safe prime, which is k bits long"""
    q = gen_n(k-1)
    while not (is_prime(q, k) and is_prime(2 * q + 1, k)):
        q = gen_n(k-1)

    return 2 * q + 1


#########################
# CRYPTOGRAPHIC FUNCTIONS
#########################


def pulverize(a: int, b: int) -> (int, int):
    """Uses the pulverizer of Aryabhatta on a pair of co-prime integers."""
    if a < b:
        a, b = b, a

    q, r = divmod(a, b)
    x1, y1, x2, y2 = 1, 0, 0, 1

    while r != 0:
        new_x2 = x1 - q * x2
        new_y2 = y1 - q * y2
        a, b = b, r
        x1, y1 = x2, y2
        x2, y2 = new_x2, new_y2
        q, r = divmod(a, b)

    return x2, y2


def factor(n: int) -> [int]:
    """Use a simple and pretty slow method to find factors of a given number"""
    factors = []

    for i in range(2, math.ceil(n / 2) + 1):
        while n % i == 0:
            n /= i
            factors.append(i)

    if not factors:
        return [n]
    else:
        return factors


def totient(n: int) -> int:
    """Euler's totient function from the unique prime factors of n"""
    if n == 1:
        return 1

    # remove duplicate prime factors
    factors = list(dict.fromkeys(factor(n)))

    product = n
    for p in factors:
        product *= (1 - 1/p)

    return int(product)


#########################
# DATA HANDLING FUNCTIONS
#########################


def ingest_data(filename: str, delimiter=None, return_type=None):
    """Reads data from the file specified by a given filename.
    Optional parameter delimiter splits the data into a list.
    Optional parameter return_type maps some type cast to the list if a delimiter was used."""
    with open(filename) as f:
        data = f.read()
    if delimiter:
        data = data.split(delimiter)
        if return_type:
            data = list(map(return_type, data))
    return data


def write_file(text: str, filename: str):
    """A simple helper function to write a string to a output file."""
    with open(filename, 'w') as f:
        f.write(text)


def write_list(data: list, filename: str):
    """A simple helper function to write a list to an output file."""
    with open(filename, 'w') as f:
        for i in range(len(data)):
            f.write(str(data[i]) + '\n' * (i != len(data) - 1))
