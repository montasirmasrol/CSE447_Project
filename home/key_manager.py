# import os

# KEY_FILE = "encryption_key.key"

# def get_encryption_key():
#     """
#     Return a 16-byte AES key.
#     Generates one if it doesn't exist and stores it in KEY_FILE.
#     """
#     if os.path.exists(KEY_FILE):
#         with open(KEY_FILE, "rb") as f:
#             key = f.read()
#     else:
#         key = os.urandom(16)  # 16 bytes = 128-bit key for AES
#         with open(KEY_FILE, "wb") as f:
#             f.write(key)
#     return key


import os

AES_KEY_FILE = "encryption_key.key"
MAC_KEY_FILE = "mac_key.key"

def get_encryption_key():
    if os.path.exists(AES_KEY_FILE):
        with open(AES_KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = os.urandom(16)
        with open(AES_KEY_FILE, "wb") as f:
            f.write(key)
    return key

def get_mac_key():
    if os.path.exists(MAC_KEY_FILE):
        with open(MAC_KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = os.urandom(16)
        with open(MAC_KEY_FILE, "wb") as f:
            f.write(key)
    return key
