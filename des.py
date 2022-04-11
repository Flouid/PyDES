

class DES:
    """A class to implement the DES system of encryption.
    Works by initializing with a 64-bit key. Any other length will cause errors.
    Keys are stored as a bitstring of length 64. This string is made by converting
    each character to a bytestring and concatenating them all together."""
    __key = str

    def __init__(self, key: str):
        # the key MUST be 64-bits long, error if this isn't the case
        assert len(key) == 8

        bitstring = ''
        for c in key:
            # convert the character to ascii integer, convert that to binary, and remove the leading '0b'
            bytestring = bin(ord(c))[2:]
            # zero-pad the front of the bytestring to guarantee exactly 8 bits
            bitstring += ('0' * (8 - len(bytestring))) + bytestring

        # additional check to ensure that the resulting bitstring is exactly 64 bits
        assert len(bitstring) == 64

        self.__key = bitstring

    def __str__(self):
        """An output method for the DES system for the purpose of debugging and validation."""
        return f'{len(self.__key)}:\t{self.__key}'
