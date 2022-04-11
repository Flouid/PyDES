

class Bitstring:
    """A class to represent the bitstring data type.
    Bitstrings MUST be exactly 64-bits. This means the input must be a string with 8 characters."""
    __bits = str

    def __init__(self, string):
        """Converts an 8-character message chunk into a 64-bit bitstring."""
        # bitstrings MUST be 64-bits long, error if this isn't the case
        assert len(string) == 8

        bitstring = ''
        for c in string:
            # convert the character to ascii integer, convert that to binary, and remove the leading '0b'
            bytestring = bin(ord(c))[2:]
            # zero-pad the front of the bytestring to guarantee exactly 8 bits
            bitstring += ('0' * (8 - len(bytestring))) + bytestring

        # additional check to ensure that the resulting bitstring is exactly 64 bits
        assert len(bitstring) == 64
        self.__bits = bitstring

    def __str__(self):
        """Returns the bitstring for output."""
        return self.__bits

    def __repr__(self):
        """Returns the bitstring for specialized printing scenarios."""
        return self.__bits
