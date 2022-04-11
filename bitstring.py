

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
            # zero pad front of the bytestring up to seven bits
            bytestring = '0' * (7 - len(bytestring)) + bytestring

            # calculate and add the parity bit so that parity is always odd
            parity = 0
            for b in bytestring:
                parity += b == '1'
            # if the parity is odd, add a zero to keep it that way, otherwise make it odd
            if parity & 1:
                bytestring += '0'
            else:
                bytestring += '1'

            # append the byte to the overall bitstring
            bitstring += bytestring

        # additional check to ensure that the resulting bitstring is exactly 64 bits
        assert len(bitstring) == 64
        self.__bits = bitstring

    def __str__(self):
        """Returns the bitstring for output."""
        return self.__bits

    def __repr__(self):
        """Returns the bitstring for specialized printing scenarios."""
        return self.__bits

    def __getitem__(self, key):
        """Allows accessing of the bitstring like a list using the [] operator."""
        return int(self.__bits[key])
