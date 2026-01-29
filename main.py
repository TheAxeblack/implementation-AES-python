# coding: utf-8
from __future__ import annotations

from typing import Final

"""
Implementation d'AES sur 128 bits
"""

NB: Final[int] = 4
NK: Final[int] = 4
NR: Final[int] = 10

Byte = int
Word = list[Byte]
State = list[Byte]
KeySchedule = list[Word]

key: list[Byte] = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C]
key2: list[Byte] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]

message: list[Byte] = [0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34]
message2: list[Byte] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]

S_Box: Final[list[list[Byte]]] = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16],
]

Inv_S_Box: Final[list[list[Byte]]] = [
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D],
]


def gmul(a: Byte, b: Byte) -> Byte:
    """Multiplication dans GF(2^8)"""
    p: Byte = 0
    byte_size: int = 8

    # Parcours de tous les bits de l'octet
    for _ in range(byte_size):
        # Comparaison du bit de poids faible de b
        if b & 1:
            p ^= a

        # Récupération du bit de poids fort de a
        hi = a & 0x80

        a = (a << 1) & 0xFF

        # Si le bit de poids fort était à 1, on effectue la réduction modulo le polynôme irréductible
        if hi:
            a ^= 0x1B

        # Passage au bit suivant
        b >>= 1
    return p


def cypher(state: State, round_keys: list[State]) -> State:
    print("\n=== Starting Cypher Process... ===")
    print("[DEBUG] Round number input;", end="\n\t")
    print("State:", end=" ")
    print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")
    print("With Round Key:", end=" ")
    print(" ".join(f"{byte:02X}" for byte in round_keys[0]))

    state = add_round_key(state, round_keys[0])
    for round in range(1, NR):
        print("[DEBUG] Round number", round, end="\n\t")
        print("Round state input:", end=" ")
        print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")
        state = sub_bytes(state)
        print("After SubBytes:", end=" ")
        print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")
        state = shift_rows(state)
        print("After ShiftRows:", end=" ")
        print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")
        state = mix_columns(state)
        print("After MixColumns:", end=" ")
        print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")
        state = add_round_key(state, round_keys[round])
        print("With Round Key:", end=" ")
        print(" ".join(f"{byte:02X}" for byte in round_keys[round]))

    state = sub_bytes(state)
    print("[DEBUG] Final Round;", end="\n\t")
    print("Round state input:", end=" ")
    print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")
    state = shift_rows(state)
    print("After ShiftRows:", end=" ")
    print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")
    state = add_round_key(state, round_keys[NR])
    print("With Round Key:", end=" ")
    print(" ".join(f"{byte:02X}" for byte in round_keys[NR]))
    print("=== Cypher Process Completed. ===")
    return state


def sub_bytes(state: State) -> State:
    new_state: State = []

    for byte in state:
        if len(hex(byte)) < 4:
            x = 0
            y = int(hex(byte)[2], 16)
        else:
            x = int(hex(byte)[2], 16)
            y = int(hex(byte)[3], 16)
        new_state.append(S_Box[x][y])
    return new_state


def shift_rows(state: State) -> State:
    # Transformation du message d'entrée en matrice
    m = [state[i::NB] for i in range(NB)]

    # Décalage des lignes
    for i in range(1, NB):
        m[i] = m[i][i:] + m[i][:i]

    # Transformation de la matrice en message de sortie
    new_state = [m[r][c] for c in range(NB) for r in range(NB)]
    return new_state


def mix_columns(state: State) -> State:
    # Création de la matrice à partir de l'état d'entrée (4*4)
    m = [state[i::NB] for i in range(NB)]

    # Création de la matrice résultat
    result = [[0] * NB for _ in range(NB)]

    for c in range(NB):  # pour chaque colonne
        col = [m[r][c] for r in range(NB)]
        result[0][c] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3]
        result[1][c] = col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3]
        result[2][c] = col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3)
        result[3][c] = gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2)

    # Transformation de la matrice résultat en état de sortie
    new_state = [result[r][c] for c in range(NB) for r in range(NB)]
    return new_state


def add_round_key(state: State, round_key: State) -> State:
    # Operation XOR (^) sur tous les elements du message d'entrée et de la clé
    return [a ^ b for a, b in zip(state, round_key)]


def sub_word(word: Word) -> Word:
    result: State = []
    for byte in word:
        if len(hex(byte)) < 4:
            x = 0
            y = int(hex(byte)[2], 16)
        else:
            x = int(hex(byte)[2], 16)
            y = int(hex(byte)[3], 16)
        result.append(S_Box[x][y])
    return result


def rot_word(word: Word) -> Word:
    return word[1:] + word[:1]


def xor_words(w1: Word, w2: Word) -> Word:
    return [a ^ b for a, b in zip(w1, w2)]


def rcon(i: int) -> Word:
    c = 0x01
    for _ in range(i - 1):
        c <<= 1
        if c & 0x100:
            c ^= 0x11B
    return [c & 0xFF, 0x00, 0x00, 0x00]


def key_expansion(key: State) -> KeySchedule:
    print("\n=== Starting Key Expansion... ===")
    w: KeySchedule = [None] * (NB * (NR + 1))  # type: ignore[list-item]

    i = 0
    while i < NK:
        w[i] = key[4 * i: 4 * i + 4]
        i += 1

    i = NK

    while i < NB * (NR + 1):
        temp = w[i - 1]
        print("[DEBUG] i (dec):", i, end=" ")
        print(" temp :", end=" ")
        print("".join(f"{byte:02X}" for byte in temp), end=" ")
        if i % NK == 0:
            print("after rot_word:", end=" ")
            print("".join(f"{byte:02X}" for byte in temp), end=" ")
            temp = sub_word(rot_word(temp))
            print("after sub_word:", end=" ")
            print("".join(f"{byte:02X}" for byte in temp), end=" ")
            print("Rcon[i/NK]:", end=" ")
            print("".join(f"{byte:02X}" for byte in rcon(int(i / NK))), end=" ")
            temp = xor_words(temp, rcon(i // NK))
            print("After XOR with Rcon :", end=" ")
            print("".join(f"{byte:02X}" for byte in temp), end=" ")
        elif NK > 6 and i % NK == 4:
            temp = sub_word(temp)

        w[i] = xor_words(w[i - NK], temp)
        print("[DEBUG] w[i] :", end=" ")
        print("".join(f"{byte:02X}" for byte in w[i]))
        i += 1

    print("=== Key Expansion Completed. ===\n")
    return w


def inv_cypher(state: State, round_keys: list[State]) -> State:
    print("=== Starting Inverse Cypher Process... ===")
    print("[DEBUG] Round number input;", end="\n\t")
    print("State:", end=" ")
    print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")
    print("With Round Key:", end=" ")
    print(" ".join(f"{byte:02X}" for byte in round_keys[NR]))

    state = add_round_key(state, round_keys[NR])

    for round in range(NR - 1, 0, -1):
        print("[DEBUG] Round number", round, end="\n\t")
        print("Round state input:", end=" ")
        print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")

        state = inv_shift_rows(state)

        print("After InvShiftRows:", end=" ")
        print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")

        state = inv_sub_bytes(state)

        print("After InvSubBytes:", end=" ")
        print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")

        state = add_round_key(state, round_keys[round])
        print("With Round Key:", end=" ")
        print(" ".join(f"{byte:02X}" for byte in round_keys[round]), end="\n\t")

        state = inv_mix_columns(state)
        print("After InvMixColumns:", end=" ")
        print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")

    print("[DEBUG] Final Round;", end="\n\t")
    print("Round state input:", end=" ")
    print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")

    state = inv_shift_rows(state)
    print("After InvShiftRows:", end=" ")
    print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")

    state = inv_sub_bytes(state)
    print("After InvSubBytes:", end=" ")
    print(" ".join(f"{byte:02X}" for byte in state), end="\n\t")

    state = add_round_key(state, round_keys[0])
    print("With Round Key:", end=" ")
    print(" ".join(f"{byte:02X}" for byte in round_keys[0]))
    print("=== Inverse Cypher Process Completed. ===")

    return state


def inv_shift_rows(state: State) -> State:
    m = [state[i::NB] for i in range(NB)]

    for i in range(1, NB):
        m[i] = m[i][-i:] + m[i][:-i]

    new_state = [m[r][c] for c in range(NB) for r in range(NB)]
    return new_state


def inv_sub_bytes(state: State) -> State:
    new_state: State = []

    for byte in state:
        x = byte >> 4
        y = byte & 0x0F
        new_state.append(Inv_S_Box[x][y])

    return new_state


def inv_mix_columns(state: State) -> State:
    m = [state[i::NB] for i in range(NB)]
    result = [[0] * NB for _ in range(NB)]

    for c in range(NB):
        col = [m[r][c] for r in range(NB)]
        result[0][c] = (
                gmul(col[0], 0x0E)
                ^ gmul(col[1], 0x0B)
                ^ gmul(col[2], 0x0D)
                ^ gmul(col[3], 0x09)
        )
        result[1][c] = (
                gmul(col[0], 0x09)
                ^ gmul(col[1], 0x0E)
                ^ gmul(col[2], 0x0B)
                ^ gmul(col[3], 0x0D)
        )
        result[2][c] = (
                gmul(col[0], 0x0D)
                ^ gmul(col[1], 0x09)
                ^ gmul(col[2], 0x0E)
                ^ gmul(col[3], 0x0B)
        )
        result[3][c] = (
                gmul(col[0], 0x0B)
                ^ gmul(col[1], 0x0D)
                ^ gmul(col[2], 0x09)
                ^ gmul(col[3], 0x0E)
        )

    new_state = [result[r][c] for c in range(NB) for r in range(NB)]
    return new_state


def main(inp: State, key: State) -> None:
    print("Input :", end=" ")
    print(" ".join(f"{byte:02X}" for byte in inp))
    print("Cypher Key :", end=" ")
    print(" ".join(f"{byte:02X}" for byte in key))

    # Test pour une seule itération d'AES
    # state = add_round_key(inp, key)
    # print("[DEBUG] step add_round_key :", end=" ")
    # print(" ".join(f"{byte:02X}" for byte in state))
    # state = sub_bytes(state)
    # print("[DEBUG] step sub_bytes :", end=" ")
    # print(" ".join(f"{byte:02X}" for byte in state))
    # state = shift_rows(state)
    # print("[DEBUG] step shift_rows :", end=" ")
    # print(" ".join(f"{byte:02X}" for byte in state))
    # state = mix_columns(state)
    # print("[DEBUG] step mix_columns :", end=" ")
    # print(" ".join(f"{byte:02X}" for byte in state))
    # state = add_round_key(state, key2)
    # print("[DEBUG] step add_round_key :", end=" ")
    # print(" ".join(f"{byte:02X}" for byte in state), end="\n\n")

    # === Full AES Cypher Test ===
    expanded_keys = key_expansion(key)

    # === Affichage de debug des clés générées ===
    print("\n[DEBUG] Expanded Keys:")
    for i in range(NR + 1):
        round_key = []
        for j in range(NB):
            round_key.extend(expanded_keys[i * NB + j])
        print(f"\tRound {i} Key: " + " ".join(f"{byte:02X}" for byte in round_key))

    # Construction des clés de chaque round à partir des clés générées
    round_keys: list[State] = []
    for i in range(NR + 1):
        round_key: State = []
        for j in range(NB):
            round_key.extend(expanded_keys[i * NB + j])
        round_keys.append(round_key)

    # Chiffrage du message d'entrée avec les clés de chaque round
    encrypted_state = cypher(inp, round_keys)

    # === Affichage du résultat ===
    print("\nEncrypted State :", end=" ")
    print(" ".join(f"{byte:02X}" for byte in encrypted_state), end="\n\n")

    # Déchiffrage du message chiffré avec les clés de chaque round
    decrypted_state = inv_cypher(encrypted_state, round_keys)

    # === Affichage du résultat ===
    print("Decrypted State :", end=" ")
    print(" ".join(f"{byte:02X}" for byte in decrypted_state))

    print("Is decrypted state equal to input?", end=" ")
    print("Yes it is" if decrypted_state == inp else "No")

    return None


if __name__ == "__main__":
    main(message, key)
    exit(0)
