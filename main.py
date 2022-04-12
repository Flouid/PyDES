from time import time
from des import DES


def main():
    key = 'abcdefgh'
    des = DES(key)

    message = 'This is a decently long test message of no particular length.'

    encrypted_message = des.encrypt(message)

    print(len(message), message)
    print(len(encrypted_message), encrypted_message)


if __name__ == '__main__':
    start = time()
    main()
    print('\nFINISHED IN %s SECONDS' % round(time() - start, 4))
