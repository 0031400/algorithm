def pad_func(a: bytes) -> bytes:
    init_l: int = len(a)
    a += b"\x80"
    a = a + b"\x00" * ((56 - len(a) % 64) % 64)
    a += int.to_bytes(init_l * 8, 8, "big")
    return a


def rotl(a: int, l: int) -> int:
    return ((a >> (32 - l)) | (a << l)) & 0xFFFFFFFF


def k(t: int) -> int:
    if t < 0:
        print("k is wrong")
        return 0
    elif t < 20:
        return 0x5A827999
    elif t < 40:
        return 0x6ED9EBA1
    elif t < 60:
        return 0x8F1BBCDC
    elif t < 80:
        return 0xCA62C1D6
    else:
        print("k is wrong")
        return 0


def f(x: int, y: int, z: int, t: int) -> int:
    if t < 0:
        print("k is wrong")
        return 0
    elif t < 20:
        return (x & y) | ((~x) & z)
    elif t < 40:
        return x ^ y ^ z
    elif t < 60:
        return (x & y) | (x & z) | (y & z)
    elif t < 80:
        return x ^ y ^ z
    else:
        print("f is wrong")
        return 0


def sha1_func(input: bytes) -> bytes:
    x: bytes = pad_func(input)
    blocks: list[bytes] = [x[i : i + 64] for i in range(0, len(x), 64)]
    h_list: list[int] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    ]
    for ii in range(len(blocks)):
        block: bytes = blocks[ii]
        m_list: list[bytes] = [block[i : i + 4] for i in range(0, 64, 4)]
        w_list: list[int] = [int.from_bytes(i, "big") for i in m_list]
        for t in range(16, 80):
            w_list.append(
                rotl(w_list[t - 3] ^ w_list[t - 8] ^ w_list[t - 14] ^ w_list[t - 16], 1)
            )
        [a, b, c, d, e] = h_list
        for t in range(0, 80):
            temp: int = (rotl(a, 5) + f(b, c, d, t) + e + k(t) + w_list[t]) & 0xFFFFFFFF
            e = d
            d = c
            c = rotl(b, 30)
            b = a
            a = temp
        h_list[0] = (h_list[0] + a) & 0xFFFFFFFF
        h_list[1] = (h_list[1] + b) & 0xFFFFFFFF
        h_list[2] = (h_list[2] + c) & 0xFFFFFFFF
        h_list[3] = (h_list[3] + d) & 0xFFFFFFFF
        h_list[4] = (h_list[4] + e) & 0xFFFFFFFF
    return b"".join(h.to_bytes(4, "big") for h in h_list)


if __name__ == "__main__":
    input: bytes = "Zab".encode()
    print(bytes.hex(sha1_func(input)))
