from sha1_func import pad_func, rotl


def rotr(a: int, l: int) -> int:
    return ((a << (32 - l)) | (a >> l)) & 0xFFFFFFFF


def K(a: int) -> int:
    l = [
        0x428A2F98,
        0x71374491,
        0xB5C0FBCF,
        0xE9B5DBA5,
        0x3956C25B,
        0x59F111F1,
        0x923F82A4,
        0xAB1C5ED5,
        0xD807AA98,
        0x12835B01,
        0x243185BE,
        0x550C7DC3,
        0x72BE5D74,
        0x80DEB1FE,
        0x9BDC06A7,
        0xC19BF174,
        0xE49B69C1,
        0xEFBE4786,
        0x0FC19DC6,
        0x240CA1CC,
        0x2DE92C6F,
        0x4A7484AA,
        0x5CB0A9DC,
        0x76F988DA,
        0x983E5152,
        0xA831C66D,
        0xB00327C8,
        0xBF597FC7,
        0xC6E00BF3,
        0xD5A79147,
        0x06CA6351,
        0x14292967,
        0x27B70A85,
        0x2E1B2138,
        0x4D2C6DFC,
        0x53380D13,
        0x650A7354,
        0x766A0ABB,
        0x81C2C92E,
        0x92722C85,
        0xA2BFE8A1,
        0xA81A664B,
        0xC24B8B70,
        0xC76C51A3,
        0xD192E819,
        0xD6990624,
        0xF40E3585,
        0x106AA070,
        0x19A4C116,
        0x1E376C08,
        0x2748774C,
        0x34B0BCB5,
        0x391C0CB3,
        0x4ED8AA4A,
        0x5B9CCA4F,
        0x682E6FF3,
        0x748F82EE,
        0x78A5636F,
        0x84C87814,
        0x8CC70208,
        0x90BEFFFA,
        0xA4506CEB,
        0xBEF9A3F7,
        0xC67178F2,
    ]
    return l[a]


def sum_0(a: int) -> int:
    return rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)


def sum_1(a: int) -> int:
    return rotr(a, 6) ^ rotr(a, 11) ^ rotr(a, 25)


def sigma_0(a: int) -> int:
    return rotr(a, 7) ^ rotr(a, 18) ^ (a >> 3)


def sigma_1(a: int) -> int:
    return rotr(a, 17) ^ rotr(a, 19) ^ (a >> 10)


def Ch(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (((~x) & 0xFFFFFFFF) & z)) & 0xFFFFFFFF


def Maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def sha256_func(input: bytes) -> bytes:
    x: bytes = pad_func(input)
    blocks: list[bytes] = [x[i : i + 64] for i in range(0, len(x), 64)]
    h_list: list[int] = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]
    for ii in range(len(blocks)):
        block: bytes = blocks[ii]
        m_list: list[bytes] = [block[i : i + 4] for i in range(0, 64, 4)]
        w_list: list[int] = [int.from_bytes(i, "big") for i in m_list]
        for t in range(16, 64):
            w_list.append(
                (
                    sigma_1(w_list[t - 2])
                    + w_list[t - 7]
                    + sigma_0(w_list[t - 15])
                    + w_list[t - 16]
                )
                & 0xFFFFFFFF
            )
        [a, b, c, d, e, f, g, h] = h_list
        for t in range(0, 64):
            temp_1: int = (h + sum_1(e) + Ch(e, f, g) + K(t) + w_list[t]) & 0xFFFFFFFF
            temp_2: int = (sum_0(a) + Maj(a, b, c)) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + temp_1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp_1 + temp_2) & 0xFFFFFFFF
        h_list[0] = (h_list[0] + a) & 0xFFFFFFFF
        h_list[1] = (h_list[1] + b) & 0xFFFFFFFF
        h_list[2] = (h_list[2] + c) & 0xFFFFFFFF
        h_list[3] = (h_list[3] + d) & 0xFFFFFFFF
        h_list[4] = (h_list[4] + e) & 0xFFFFFFFF
        h_list[5] = (h_list[5] + f) & 0xFFFFFFFF
        h_list[6] = (h_list[6] + g) & 0xFFFFFFFF
        h_list[7] = (h_list[7] + h) & 0xFFFFFFFF
    return b"".join(h.to_bytes(4, "big") for h in h_list)


if __name__ == "__main__":
    input: bytes = b"abc"
    print(bytes.hex(sha256_func(input)))
