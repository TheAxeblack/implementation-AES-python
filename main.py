# coding: utf-8

from typing import Any

"""
Implementation d'AES sur 128 bits
"""

NB: int = 4
NK: int = 4
NR: int = 10

key: list[str] = [
    "0x2b",
    "0x7e",
    "0x15",
    "0x16",
    "0x28",
    "0xae",
    "0xd2",
    "0xa6",
    "0xab",
    "0xf7",
    "0x15",
    "0x88",
    "0x09",
    "0xcf",
    "0x4f",
    "0x3c",
]

key2: list[str] = [
    "0xA0",
    "0xfa",
    "0xfe",
    "0x17",
    "0x88",
    "0x54",
    "0x2c",
    "0xb1",
    "0x23",
    "0xa3",
    "0x39",
    "0x39",
    "0x2a",
    "0x6c",
    "0x76",
    "0x05",
]

message: list[str] = [
    "0x32",
    "0x43",
    "0xf6",
    "0xa8",
    "0x88",
    "0x5a",
    "0x30",
    "0x8d",
    "0x31",
    "0x31",
    "0x98",
    "0xa2",
    "0xe0",
    "0x37",
    "0x07",
    "0x34",
]

S_Box: list[list[str]] = [
    [
        "0x63",
        "0x7C",
        "0x77",
        "0x7B",
        "0xF2",
        "0x6B",
        "0x6F",
        "0xC5",
        "0x30",
        "0x01",
        "0x67",
        "0x2B",
        "0xFE",
        "0xD7",
        "0xAB",
        "0x76",
    ],
    [
        "0xCA",
        "0x82",
        "0xC9",
        "0x7D",
        "0xFA",
        "0x59",
        "0x47",
        "0xF0",
        "0xAD",
        "0xD4",
        "0xA2",
        "0xAF",
        "0x9C",
        "0xA4",
        "0x72",
        "0xC0",
    ],
    [
        "0xB7",
        "0xFD",
        "0x93",
        "0x26",
        "0x36",
        "0x3F",
        "0xF7",
        "0xCC",
        "0x34",
        "0xA5",
        "0xE5",
        "0xF1",
        "0x71",
        "0xD8",
        "0x31",
        "0x15",
    ],
    [
        "0x04",
        "0xC7",
        "0x23",
        "0xC3",
        "0x18",
        "0x96",
        "0x05",
        "0x9A",
        "0x07",
        "0x12",
        "0x80",
        "0xE2",
        "0xEB",
        "0x27",
        "0xB2",
        "0x75",
    ],
    [
        "0x09",
        "0x83",
        "0x2C",
        "0x1A",
        "0x1B",
        "0x6E",
        "0x5A",
        "0xA0",
        "0x52",
        "0x3B",
        "0xD6",
        "0xB3",
        "0x29",
        "0xE3",
        "0x2F",
        "0x84",
    ],
    [
        "0x53",
        "0xD1",
        "0x00",
        "0xED",
        "0x20",
        "0xFC",
        "0xB1",
        "0x5B",
        "0x6A",
        "0xCB",
        "0xBE",
        "0x39",
        "0x4A",
        "0x4C",
        "0x58",
        "0xCF",
    ],
    [
        "0xD0",
        "0xEF",
        "0xAA",
        "0xFB",
        "0x43",
        "0x4D",
        "0x33",
        "0x85",
        "0x45",
        "0xF9",
        "0x02",
        "0x7F",
        "0x50",
        "0x3C",
        "0x9F",
        "0xA8",
    ],
    [
        "0x51",
        "0xA3",
        "0x40",
        "0x8F",
        "0x92",
        "0x9D",
        "0x38",
        "0xF5",
        "0xBC",
        "0xB6",
        "0xDA",
        "0x21",
        "0x10",
        "0xFF",
        "0xF3",
        "0xD2",
    ],
    [
        "0xCD",
        "0x0C",
        "0x13",
        "0xEC",
        "0x5F",
        "0x97",
        "0x44",
        "0x17",
        "0xC4",
        "0xA7",
        "0x7E",
        "0x3D",
        "0x64",
        "0x5D",
        "0x19",
        "0x73",
    ],
    [
        "0x60",
        "0x81",
        "0x4F",
        "0xDC",
        "0x22",
        "0x2A",
        "0x90",
        "0x88",
        "0x46",
        "0xEE",
        "0xB8",
        "0x14",
        "0xDE",
        "0x5E",
        "0x0B",
        "0xDB",
    ],
    [
        "0xE0",
        "0x32",
        "0x3A",
        "0x0A",
        "0x49",
        "0x06",
        "0x24",
        "0x5C",
        "0xC2",
        "0xD3",
        "0xAC",
        "0x62",
        "0x91",
        "0x95",
        "0xE4",
        "0x79",
    ],
    [
        "0xE7",
        "0xC8",
        "0x37",
        "0x6D",
        "0x8D",
        "0xD5",
        "0x4E",
        "0xA9",
        "0x6C",
        "0x56",
        "0xF4",
        "0xEA",
        "0x65",
        "0x7A",
        "0xAE",
        "0x08",
    ],
    [
        "0xBA",
        "0x78",
        "0x25",
        "0x2E",
        "0x1C",
        "0xA6",
        "0xB4",
        "0xC6",
        "0xE8",
        "0xDD",
        "0x74",
        "0x1F",
        "0x4B",
        "0xBD",
        "0x8B",
        "0x8A",
    ],
    [
        "0x70",
        "0x3E",
        "0xB5",
        "0x66",
        "0x48",
        "0x03",
        "0xF6",
        "0x0E",
        "0x61",
        "0x35",
        "0x57",
        "0xB9",
        "0x86",
        "0xC1",
        "0x1D",
        "0x9E",
    ],
    [
        "0xE1",
        "0xF8",
        "0x98",
        "0x11",
        "0x69",
        "0xD9",
        "0x8E",
        "0x94",
        "0x9B",
        "0x1E",
        "0x87",
        "0xE9",
        "0xCE",
        "0x55",
        "0x28",
        "0xDF",
    ],
    [
        "0x8C",
        "0xA1",
        "0x89",
        "0x0D",
        "0xBF",
        "0xE6",
        "0x42",
        "0x68",
        "0x41",
        "0x99",
        "0x2D",
        "0x0F",
        "0xB0",
        "0x54",
        "0xBB",
        "0x16",
    ],
]


def _morph_list_to_matrix(input_list: list[Any]) -> list[list[Any]]:
    return [input_list[i::NB] for i in range(NB)]


def cypher(inp, keys) -> Any:
    # print(inp)
    state = add_round_key(inp, keys[0])
    # print(state)

    for i in range(1, NR):
        state = sub_bytes(state)
        # print(state)
        state = shift_rows(state)
        # print(outp)
        state = mix_columns(state)
        # print(outp)
        state = add_round_key(state, keys[i])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, keys[NR])

    return state


def sub_bytes(input_message) -> list[str]:
    new_message: list[str] = []
    for part in input_message:
        if len(part) < 4:
            x: int = 0
            y: int = int(part[2], base=16)
        else:
            x: int = int(part[2], base=16)
            y: int = int(part[3], base=16)

        new_part: str = S_Box[x][y]
        new_message.append(new_part)

    return new_message


def shift_rows(input_message) -> list[str]:
    # Transformation du message d'entrée en matrice
    m = _morph_list_to_matrix(input_message)

    # Décalage des lignes
    for i in range(1, NB):
        m[i] = m[i][i:] + m[i][:i]

    # Transformation de la matrice en message de sortie
    new_message: list[str] = []
    for i in range(NB):
        for j in range(NB):
            new_message.append(m[j][i])
    return new_message


def mix_columns(input_message) -> list[str]:
    def gmul(a: int, b: int) -> int:
        p = 0
        # Parcours de tous les bits de l'octet
        for _ in range(8):
            # Comparaison du bit de poids faible de b
            if b & 1:
                p ^= a

            bit_poids_fort = a & 0x80
            a = (a << 1) & 0xFF

            if bit_poids_fort:
                a ^= 0x1B

            # Passage au bit suivant
            b >>= 1
        return p

    m = _morph_list_to_matrix(input_message)

    result = [[0] * NB for _ in range(NB)]

    for c in range(NB):  # pour chaque colonne
        col = [int(m[r][c], 16) for r in range(NB)]
        result[0][c] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3]
        result[1][c] = col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3]
        result[2][c] = col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3)
        result[3][c] = gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2)

    # Retour sous forme de liste linéaire comme le reste du code
    new_message: list[str] = []
    for i in range(NB):
        for j in range(NB):
            new_message.append(hex(result[j][i]))

    return new_message


def add_round_key(input_message, key_schedule) -> list[str]:
    # Operation XOR (^) sur tous les elements du message d'entré et de la clé
    new_message: list[str] = [
        hex(
            int(part_m, base=16) ^ int(part_k, base=16),
        )
        for part_m, part_k in zip(input_message, key_schedule)
    ]
    return new_message



def key_expansion(key:list[str]):
    def sub_word(word):
        result = []
        for byte in word:
            if len(byte) < 4:
                x = 0
                y = int(byte[2], 16)
            else:
                x = int(byte[2], 16)
                y = int(byte[3], 16)
            result.append(S_Box[x][y])
        return result

    def rot_word(word):
        return word[1:] + word[:1]

    def xor_words(w1, w2):
        return [hex(int(a, 16) ^ int(b, 16)) for a, b in zip(w1, w2)]

    def gmul(a, b):
        """Multiplication dans GF(2^8)"""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B
            b >>= 1
        return p

    def rcon(i):
        return [hex(gmul(0x02, 1 << (i - 1))), "0x00", "0x00", "0x00"]

    i: int = 0

    w: list[Any]= [None] * (NB * (NR + 1))

    while i < NK:
        w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]
        i += 1

    i = NK
    
    while i < NB * (NR + 1):
        temp = w[i - 1]

        if i % NK == 0:
            temp = sub_word(rot_word(temp))
            temp = xor_words(temp, rcon(i // NK))
        elif NK > 6 and i % NK == 4:
            temp = sub_word(temp)

        w[i] = xor_words(w[i - NK], temp)
        i += 1

    return w


def main(inp) -> None:
    print(inp)
    state = add_round_key(inp, key)
    print(f"[DEBUG] step add_round_key : {state}")
    state = sub_bytes(state)
    print(f"[DEBUG] step sub_bytes : {state}")
    state = shift_rows(state)
    print(f"[DEBUG] step shift_rows : {state}")
    state = mix_columns(state)
    print(f"[DEBUG] step mix_columns : {state}")
    state = add_round_key(state, key2)
    print(f"[DEBUG] step add_round_key : {state}")


if __name__ == "__main__":
    main(message)
    
    expanded_keys = key_expansion(key)
    
    print("\n[DEBUG] Expanded Keys:")
    for i in range(NR + 1):
        round_key = []
        for j in range(NB):
            round_key.extend(expanded_keys[i * NB + j])
        print(f"Round {i} Key: {round_key}")