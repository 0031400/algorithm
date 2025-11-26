from sha1_func import sha1_func
from typing import Callable


def hmac_sha1(key: bytes, msg: bytes, sha_func: Callable[[bytes], bytes]) -> bytes:
    block_size: int = 64
    key_l: int = len(key)
    if key_l < block_size:
        key += b"\00" * (block_size - key_l)
    elif key_l > block_size:
        key = sha_func(key)
    ipad: bytes = bytes([0x36] * block_size)
    opad: bytes = bytes([0x5C] * block_size)
    k_ipad: bytes = bytes([a ^ b for a, b in zip(key, ipad)])
    k_opad: bytes = bytes([a ^ b for a, b in zip(key, opad)])
    inner: bytes = sha_func(k_ipad + msg)
    outer: bytes = sha_func(k_opad + inner)
    return outer


if __name__ == "__main__":
    key: bytes = b"key"
    msg: bytes = b"message"
    result: bytes = hmac_sha1(key, msg, sha1_func)
    print(bytes.hex(result))
