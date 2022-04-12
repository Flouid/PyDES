from utils import ingest_data


class DES:
    """A class to implement the DES system of encryption.
    Works by initializing with a 64-bit key. Any other length will cause errors.
    Keys are stored as a bitstring of length 64. Bitstrings are stored as a list of 64 integers.

    DES uses a number of hardcoded tables to perform encryption and decryption.
    These are stored as lists of indices representing which bit from the message or key
    they represent. These tables are stored and loaded from an accompanying text file."""
    __key = [int]           # parity dropped, permuted key

    # encryption/decryption tables
    __ip = [int]            # initial permutation table
    __fp = [int]            # final permutation table
    __exp = [int]           # expansion function
    __perm = [int]          # permutation table
    __s_boxes = [[int]]     # s box tables

    # key generation tables
    __kpt = [int]           # key permutation table
    __brt = [int]           # bit rotation table
    __kct = [int]           # key compression table

    def __init__(self, key: str):
        # load the tables in from the text file
        rows = ingest_data('des_tables.txt', '\n')

        # f-box tables
        self.__ip = list(map(int, rows[0].split()))
        self.__fp = list(map(int, rows[1].split()))
        self.__exp = list(map(int, rows[2].split()))
        self.__perm = list(map(int, rows[3].split()))
        # s boxes
        self.__s_boxes = []
        for i in range(4, 12):
            self.__s_boxes.append(list(map(int, rows[i].split())))
        # key generation tables
        self.__kpt = list(map(int, rows[12].split()))
        self.__brt = list(map(int, rows[13].split()))
        self.__kct = list(map(int, rows[14].split()))

        # convert the key into a 64-bit bitstring
        key_bitstring = self.__string_to_bits(key)
        # use the key permutation table to create the main key which will be used for sub-keys
        permuted_key = []
        for i in self.__kpt:
            permuted_key.append(key_bitstring[i])

        self.__key = permuted_key

    def __str__(self):
        """An output method for the DES system for the purpose of debugging and validation."""
        string = ''
        string += f'key = {len(self.__key)}:\t{self.__key}\n'
        string += f'initial permutation = {len(self.__ip)}:\t{self.__ip}\n'
        string += f'final permutation = {len(self.__fp)}:\t{self.__fp}\n'
        string += f'expansion table = {len(self.__exp)}:\t{self.__exp}\n'
        string += f'permutation table = {len(self.__perm)}:\t{self.__perm}\n'
        for i in range(len(self.__s_boxes)):
            string += f's_box{i+1} = {len(self.__s_boxes[i])}:\t{self.__s_boxes[i]}\n'
        string += f'key permutation table = {len(self.__kpt)}:\t{self.__kpt}\n'
        string += f'bit rotation table = {len(self.__brt)}:\t{self.__brt}\n'
        string += f'key compression table = {len(self.__kct)}:\t{self.__kct}\n'

        return string

    @staticmethod
    def __string_to_bits(string: str) -> [int]:
        """Converts an 8-character message chunk into a 64-bit bitstring.
        Uses parity bits to pad 7-bit ascii codes to create full bytes."""
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
        # return the bitstring as a list of integers
        return list(map(int, bitstring))

    @staticmethod
    def __bits_to_string(bits: [int]) -> str:
        """Converts a 64-bit bitstring to an 8-character message chunk.
        Drops parity bits and uses 8 7-bit ascii codes for the mapping."""
        # bitstrings MUST be 64-bits long, error if this isn't the case
        assert len(bits) == 64

        string = ''
        for chunk in range(8):
            # grab each byte as a list of 8 bits from the input
            byte = bits[chunk * 8: chunk * 8 + 8]
            # convert the byte to a string and strip the last (parity) bit
            bytestring = '0b' + ''.join(map(str, byte[:8]))
            # convert the byte to an ascii code and add the character it represents to the output string
            string += chr(int(bytestring[2:], 2))

        # make sure the length of the string is 8 as a sanity check
        assert len(string) == 8

        return string

    def __chunk_message(self, m: str) -> [[int]]:
        """Takes a full-length message and chunks it into a list of bitstrings.
        The last bitstring is padded with null characters to make it the correct length."""
        chunks = []

        # process all complete chunks
        for chunk in range(len(m) // 8):
            chunks.append(self.__string_to_bits(m[(8 * chunk):(8 * chunk + 8)]))

        # process a possible partial chunk at the end
        pad = (8 - len(m) % 8) % 8
        if pad > 0:
            # take the last 8-pad characters and zero pad a new chunk with null characters
            chunks.append(self.__string_to_bits(m[-(8 - pad):] + (chr(0) * pad)))

        return chunks

    def __merge_message(self, blocks: [[int]]) -> str:
        """Reverses the chunk-message operation by taking a list of bitstrings and merging them to a string.
        The last string will be padded with null characters that get chopped off later."""
        return ''.join([self.__bits_to_string(bitstring) for bitstring in blocks])

    def encrypt(self, m: str):
        """The main public-facing function to encrypt a message.
        Uses the DES encryption standard and encrypts blocks one at a time using 16 rounds of feistel ciphers."""
        blocks = self.__chunk_message(m)
        encrypted_blocks = []

        for block in blocks:
            # run the initial permutation, the result is a list of integers encoded as bits
            ip = []
            for i in self.__ip:
                ip.append(block[i-1])

            # initialize the input blocks prior to running feistel rounds
            l1, r1 = ip[:32], ip[32:]

            # run the 16 rounds of feistel ciphers
            for r in range(16):
                # define l0 and r0 as the output from the previous round
                l0, r0 = l1, r1
                # run the feistel cipher using the f-box for the round
                l1, r1 = r0, [l0[i] ^ self.__f_box(r, r0)[i] for i in range(32)]

            # compose and append the resulting output to the encrypted blocks
            encrypted_blocks.append(l1 + r1)

        # merge the message from bitstrings back into an encrypted string
        # the output will have a length that is a multiple of 8, only take as many characters as were in the input
        return self.__merge_message(encrypted_blocks)[:len(m)]

    def __f_box(self, r: int, bits: [int]) -> [int]:
        """Runs the appropriate f-box for a given round on an input block of 32 bits."""
        # run the 32-bit block through the expansion table to create a 48-bit block
        exp = []
        for i in self.__exp:
            exp.append(bits[i-1])

        # get the 48-bit sub-key for the round
        sub_key = self.__sub_key(r)

        # xor the sub-key with the expanded input block
        block = [exp[i] ^ sub_key[i] for i in range(48)]

        # split the block into 8 6-bit sub-blocks and run each through their respective s-box
        # compose the resulting 4-bit blocks into a 32-bit output block
        out = []
        for s in range(8):
            # isolate row and column indices
            row_bits = [block[6 * s], block[6 * s + 5]]        # first and last bits of the block
            col_bits = block[6*s + 1: 6*s + 5]                 # middle four bits of the block
            # convert the bits to integer indices
            row = int('0b' + ''.join(map(str, row_bits)), 2)
            col = int('0b' + ''.join(map(str, col_bits)), 2)
            # get the 4-bit integer in the correct s-box specified by the row and column indices
            val = self.__s_boxes[s][row * 16 + col]

            # convert the value into a bitstring of exactly length 4 by zero-padding the front
            bitstring = bin(val)[2:]
            bitstring = '0' * (4 - len(bitstring)) + bitstring
            # append each bit of the resulting bitstring to the output block
            for bit in bitstring:
                out.append(int(bit))

        # run the output block through the permutation table to get a final output
        final = []
        for i in self.__perm:
            final.append(out[i-1])

        return final

    def __sub_key(self, r: int) -> [int]:
        """Create the appropriate sub-key for the current round number."""
        # split the main key into two halves
        l0, r0 = self.__key[:28], self.__key[28:]
        # get the number of left rotations from the bit rotation table for the current round
        rotations = self.__brt[r]

        # apply the bit rotation table to the left and right halves and then compose them
        brt = [l0[(i + rotations) % 28] for i in range(28)] \
            + [r0[(i + rotations) % 28] for i in range(28)]

        # use the key compression table to get the sub-key for the round
        sub_key = []
        for i in self.__kct:
            sub_key.append(brt[i-1])

        return sub_key
