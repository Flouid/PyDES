from utils import ingest_data


class DES:
    """A class to implement the DES system of encryption.
    Works by initializing with a 64-bit key. Any other length will cause errors.
    Keys are stored as a bitstring of length 64. This string is made by converting
    each character to a bytestring and concatenating them all together.

    DES uses a number of hardcoded tables to perform encryption and decryption.
    These are stored as lists of indices representing which bit from the message or key
    they represent. These tables are stored and loaded from an accompanying text file."""
    __key = str             # key

    # encryption/decryption tables
    __ip = [int]            # initial permutation table
    __fp = [int]            # final permutation table
    __exp = [int]           # expansion function
    __perm = [int]          # permutation table
    __pc1 = [[int]]         # permuted choice 1
    __pc2 = [int]           # permuted choice 2
    __s_boxes = [[int]]     # s box tables

    # key generation tables
    __kpt = [int]           # key permutation table
    __brt = [int]           # bit rotation table
    __kct = [int]           # key compression table

    def __init__(self, key: str):
        # convert the key into a 64-bit bitstring
        self.__key = self.__make_bitstring(key)

        # load the tables in from the text file
        rows = ingest_data('des_tables.txt', '\n')

        # store each table
        self.__ip = list(map(int, rows[0].split()))
        self.__fp = list(map(int, rows[1].split()))
        self.__exp = list(map(int, rows[2].split()))
        self.__perm = list(map(int, rows[3].split()))
        self.__pc1 = [list(map(int, rows[4].split())), list(map(int, rows[5].split()))]
        self.__pc2 = list(map(int, rows[6].split()))
        # s boxes
        self.__s_boxes = []
        for i in range(7, 15):
            self.__s_boxes.append(list(map(int, rows[i].split())))
        # key generation tables
        self.__kpt = list(map(int, rows[15].split()))
        self.__brt = list(map(int, rows[16].split()))
        self.__kct = list(map(int, rows[17].split()))

    def __str__(self):
        """An output method for the DES system for the purpose of debugging and validation."""
        string = ''
        string += f'key = {len(self.__key)}:\t{self.__key}\n'
        string += f'initial permutation = {len(self.__ip)}:\t{self.__ip}\n'
        string += f'final permutation = {len(self.__fp)}:\t{self.__fp}\n'
        string += f'expansion table = {len(self.__exp)}:\t{self.__exp}\n'
        string += f'permutation table = {len(self.__perm)}:\t{self.__perm}\n'
        string += f'pc1 right = {len(self.__pc1[0])}:\t{self.__pc1[0]}\n'
        string += f'pc1 left = {len(self.__pc1[1])}:\t{self.__pc1[1]}\n'
        for i in range(len(self.__s_boxes)):
            string += f's_box{i+1} = {len(self.__s_boxes[i])}:\t{self.__s_boxes[i]}\n'
        string += f'key permutation table = {len(self.__kpt)}:\t{self.__kpt}\n'
        string += f'bit rotation table = {len(self.__brt)}:\t{self.__brt}\n'
        string += f'key compression table = {len(self.__kct)}:\t{self.__kct}\n'

        return string

    @staticmethod
    def __make_bitstring(m: str):
        # bowstrings MUST be 64-bits long, error if this isn't the case
        assert len(m) == 8

        bitstring = ''
        for c in m:
            # convert the character to ascii integer, convert that to binary, and remove the leading '0b'
            bytestring = bin(ord(c))[2:]
            # zero-pad the front of the bytestring to guarantee exactly 8 bits
            bitstring += ('0' * (8 - len(bytestring))) + bytestring

        # additional check to ensure that the resulting bitstring is exactly 64 bits
        assert len(bitstring) == 64
        return bitstring

