from time import time
from des import DES


def main():
    key = 'abcdefgh'
    des = DES(key)

    message = 'this is a decently long test message of no particular length'

    print(des.encrypt(message))


if __name__ == '__main__':
    start = time()
    main()
    print('\nFINISHED IN %s SECONDS' % round(time() - start, 4))
