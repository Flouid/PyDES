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
        self.__key = [key_bitstring[i-1] for i in self.__kpt]

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
    def __char_to_byte(c: chr) -> [int]:
        """Convert a character to a byte represented as a list of 8 bits."""
        b = [0] * 8
        ascii_val = ord(c)

        # perform bitwise operations to populate the list of bits
        for i in reversed(range(8)):
            b[i] = ascii_val & 1
            ascii_val = ascii_val >> 1

        return b

    @staticmethod
    def __byte_to_char(b: [int]) -> chr:
        """Convert a byte represented as a list of 8 bits to a character."""
        ascii_val = 0

        for i in reversed(range(8)):
            # if the bit at i is high, add 2 raised to the correct power
            ascii_val += b[i] * pow(2, 7-i)

        # cast the ascii value to a char and return
        return chr(ascii_val)

    def __string_to_bits(self, string: str) -> [int]:
        """Convert a set of 8 characters into a list of 64-bits by using 7-bit ascii and a parity bit."""
        # sanity check that the input string is exactly 8 characters
        assert len(string) == 8

        # initialize an empty array and append the byte-mapping of each character in the string
        bits = []
        for c in string:
            bits += self.__char_to_byte(c)

        # another sanity check that the resulting mapping was 64 bits
        assert len(bits) == 64

        return bits

    def __bits_to_string(self, bits: [int]) -> str:
        """Converts a list of 64 bits to an 8-character string.
        Drops parity bits and uses 8 7-bit ascii codes for the mapping."""
        # sanity check that the input is precisely 64 bits long
        assert len(bits) == 64

        string = ''
        for i in range(8):
            byte = bits[i * 8: i * 8 + 8]
            string += self.__byte_to_char(byte)

        # additional sanity check that the output is precisely 8 characters long
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
            # take the last 8-pad characters and pad a new chunk with null characters
            chunks.append(self.__string_to_bits(m[-(8 - pad):] + (chr(0) * pad)))

        return chunks

    def __merge_message(self, blocks: [[int]]) -> str:
        """Reverses the chunk-message operation by taking a list of bitstrings and merging them to a string.
        The last string will be padded with null characters that get chopped off later."""
        return ''.join([self.__bits_to_string(bitstring) for bitstring in blocks])

    def __f_box(self, r: int, bits: [int]) -> [int]:
        """Runs the appropriate f-box for a given round on an input block of 32 bits."""
        # run the 32-bit block through the expansion table to create a 48-bit block
        exp = [bits[i-1] for i in self.__exp]

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
        return [out[i-1] for i in self.__perm]

    def __sub_key(self, r: int) -> [int]:
        """Create the appropriate sub-key for the current round number."""
        # split the main key into two halves
        l0, r0 = self.__key[:28], self.__key[28:]
        # get the number of left rotations from the bit rotation table for the current round
        rotations = self.__brt[r]

        # apply the bit rotation table to the left and right halves and then compose them
        buffer = [l0[(i + rotations) % 28] for i in range(28)] \
               + [r0[(i + rotations) % 28] for i in range(28)]

        # use the key compression table to get the sub-key for the round
        return [buffer[i-1] for i in self.__kct]

    def __big_f(self, m: str, reverse: bool):
        """The main public-facing function to encrypt or decrypt a message.
        Uses the DES encryption standard and blocks are processed one at a time using 16 rounds of feistel ciphers.
        Whether or not the function encrypts or decrypts depends on the order of the rounds.
        This is determined using a flag that is passed into the function by public facing helper methods."""
        blocks = self.__chunk_message(m)
        encrypted_blocks = []

        # determine whether or not the function will encrypt or decrypt the message
        if reverse:
            rounds = reversed(range(16))
        else:
            rounds = range(16)

        for block in blocks:
            # run the initial permutation, the result is a list of integers encoded as bits
            buffer = [block[i-1] for i in self.__ip]

            # initialize the input blocks prior to running feistel rounds
            l1, r1 = buffer[:32], buffer[32:]

            # run the 16 rounds of feistel ciphers
            for r in rounds:
                # define l0 and r0 as the output from the previous round
                l0, r0 = l1, r1
                # run the feistel cipher using the f-box for the round
                l1, r1 = r0, [l0[i] ^ self.__f_box(r, r0)[i] for i in range(32)]

            # compose the two halves and run them through the final permutation
            buffer = l1 + r1
            buffer = [buffer[i-1] for i in self.__fp]

            # append the result to the encrypted blocks list
            encrypted_blocks.append(buffer)

        # merge the message from bitstrings back into an encrypted string
        # the output will have a length that is a multiple of 8, only take as many characters as were in the input
        return self.__merge_message(encrypted_blocks)

    def encrypt(self, m: str):
        """Public facing method to allow encryption using the big F box."""
        return self.__big_f(m, False)

    def decrypt(self, m: str):
        """Public facing method to allow decryption using the big F box."""
        return self.__big_f(m, True)
