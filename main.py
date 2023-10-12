import struct


# Функция для выполнения циклического сдвига битов
def rotate_left(val, r_bits, max_bits):
    return ((val << r_bits) | (val >> (max_bits - r_bits))) & (2 ** max_bits - 1)


# Функция для генерации раунд-ключей на основе мастер-ключа
def generate_round_keys(key):
    key_words = [key >> (i * 16) & 0xFFFF for i in range(8)]
    round_keys = []
    for i in range(44):
        if i < 8:
            round_keys.append(key_words[i])
        else:
            temp = rotate_left(round_keys[i - 1], 3, 16)
            if i % 8 == 0:
                temp ^= round_keys[i - 8]
                temp ^= 0xF3
            elif (i - 4) % 8 == 0:
                temp ^= round_keys[i - 8]
            round_keys.append(temp)
    return round_keys


def encrypt_block(block, round_keys):
    left, right = block >> 32, block & 0xFFFFFFFF
    for round_key in round_keys:
        temp = left
        left = right ^ ((left & 0xFFFFFFF) << 2) ^ ((left & 0xFFFFFFF) << 10) ^ ((left & 0xFFFFFFF) << 18) ^ (
                    (left & 0xFFFFFFF) << 24) ^ ((left & 0xFFFFFFF) << 32) ^ ((left & 0xFFFFFFF) << 40) ^ (
                           (left & 0xFFFFFFF) << 56) ^ ((left & 0xFFFFFFF) << 62)
        left = (left & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) | ((left >> 62) & 0x3)  # Маскирование и перенос старшего бита
        left ^= right
        right = temp
        right ^= (temp & 0xFFFFFFF) << 13
        right ^= (temp & 0xFFFFFFF) << 23
        right ^= (temp & 0xFFFFFFF) >> 3
        left ^= round_key
    return (left << 32) | right


def encrypt_file(input_filename, output_filename, key):
    round_keys = generate_round_keys(key)
    block_size_bytes = 8  # Размер блока данных в байтах
    with open(input_filename, 'rb') as input_file, open(output_filename, 'wb') as output_file:
        while True:
            data = input_file.read(block_size_bytes)
            if not data:
                break
            block = int.from_bytes(data, byteorder='big')
            encrypted_block = encrypt_block(block, round_keys)
            # Разбиваем зашифрованный блок на 8 байтов и записываем их в файл
            for _ in range(8):
                output_file.write((encrypted_block & 0xFF).to_bytes(1, byteorder='big'))
                encrypted_block >>= 8


def decrypt_file(input_filename, output_filename, key):
    round_keys = generate_round_keys(key)
    block_size_bytes = 8  # Размер блока данных в байтах
    with open(input_filename, 'rb') as input_file, open(output_filename, 'wb') as output_file:
        while True:
            data = input_file.read(block_size_bytes)
            if not data:
                break
            encrypted_block = 0
            for byte in data:
                encrypted_block = (encrypted_block << 8) | byte
            decrypted_block = encrypt_block(encrypted_block, round_keys)
            # Разбиваем расшифрованный блок на 8 байтов и записываем их в файл
            for _ in range(8):
                output_file.write((decrypted_block & 0xFF).to_bytes(1, byteorder='big'))
                decrypted_block >>= 8


if __name__ == "__main__":
    key = 0x1918A7550A68DF38E31
    encrypt_file('input_file.txt', 'encrypted_file.bin', key)
    decrypt_file('encrypted_file.bin', 'decrypted_file.txt', key)
