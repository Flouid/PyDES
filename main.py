from time import time
from des import DES


def main():
    key = 'abcdefgh'
    des = DES(key)

    message = 'This is a decently long test message of no particular length.'
    print(f'plaintext message =\n\tlength:\t{len(message)}\n\ttext:\t{message}')

    encrypted_message = des.encrypt(message)
    print(f'encrypted message =\n\tlength:\t{len(encrypted_message)}\n\ttext:\t{encrypted_message}')

    decrypted_message = des.decrypt(message)
    print(f'decrypted message =\n\tlength:\t{len(decrypted_message)}\n\ttext:\t{decrypted_message}')


if __name__ == '__main__':
    start = time()
    main()
    print('\nFINISHED IN %s SECONDS' % round(time() - start, 4))
