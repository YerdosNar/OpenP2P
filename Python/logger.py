def error(msg):
    print(f"\033[31m[x]\033[0m {msg}")


def success(msg):
    print(f"\033[32m[✓]\033[0m {msg}")


def warn(msg):
    print(f"\033[33m[!]\033[0m {msg}")


def info(msg):
    print(f"\033[34m[i]\033[0m {msg}")
