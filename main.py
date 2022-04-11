from time import time
from des import DES


def main():
    key = 'abcdefgh'
    des = DES(key)

    print(des)


if __name__ == '__main__':
    start = time()
    main()
    print('\nFINISHED IN %s SECONDS' % round(time() - start, 4))
