import logging
logging.basicConfig(level=logging.INFO)
class DESAlgorithm:
    def _permute(self, block, permutation):
        if len(block) * 8 < max(permutation):
            raise ValueError(f"输入块长度({len(block)*8}位)不足以进行置换(最大需要{max(permutation)}位)")
        if min(permutation) < 1:
            raise ValueError("置换表中包含无效索引(小于1)")
        
        # 验证所有置换索引是否在有效范围内
        invalid_indices = [i for i in permutation if i > len(block)*8]
        if invalid_indices:
            raise ValueError(f"置换索引越界: 置换表包含{len(invalid_indices)}个无效索引(最大允许{len(block)*8}), 例如: {invalid_indices[:3]}")
            
        # 将block转换为bit列表
        bits = []
        for byte in block:
            bits.extend([(byte >> (7-i)) & 1 for i in range(8)])
        
        # 执行置换
        permuted_bits = [bits[i-1] for i in permutation]
        
        # 将bit列表转回bytes
        result = bytearray()
        for i in range(0, len(permuted_bits), 8):
            byte = 0
            for j in range(8):
                if i+j < len(permuted_bits):
                    byte |= permuted_bits[i+j] << (7-j)
            result.append(byte)
        return bytes(result)
            
    def _feistel(self, right, subkey):
        # 扩展置换
        expanded = self._permute(right, self.expansion_permutation)
        # 与子密钥异或
        xored = bytes(a ^ b for a, b in zip(expanded, subkey))
        # S盒替换
        sbox_output = bytearray()
        for i in range(8):
            chunk = xored[i*6:(i+1)*6]
            if len(chunk) < 6:
                chunk = chunk + bytes([0]*(6-len(chunk)))
            row = ((chunk[0] & 0b100000) >> 4) | (chunk[5] & 0b000001)
            col = (chunk[1] & 0b011110) >> 1
            val = self.s_boxes[i][row*16 + col]
            sbox_output.append(val)
        # P置换
        return self._permute(sbox_output, self.p_permutation)
        
    def _generate_subkey(self, round_num):
        # 置换选择1 (PC-1)
        pc1 = [57, 49, 41, 33, 25, 17, 9,
               1, 58, 50, 42, 34, 26, 18,
               10, 2, 59, 51, 43, 35, 27,
               19, 11, 3, 60, 52, 44, 36,
               63, 55, 47, 39, 31, 23, 15,
               7, 62, 54, 46, 38, 30, 22,
               14, 6, 61, 53, 45, 37, 29,
               21, 13, 5, 28, 20, 12, 4]
        # 置换选择2 (PC-2)
        pc2 = [14, 17, 11, 24, 1, 5,
               3, 28, 15, 6, 21, 10,
               23, 19, 12, 4, 26, 8,
               16, 7, 27, 20, 13, 2,
               41, 52, 31, 37, 47, 55,
               30, 40, 51, 45, 33, 48,
               44, 49, 39, 56, 34, 53,
               46, 42, 50, 36, 29, 32]
        # 循环左移表
        shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        
        # 将密钥转换为二进制位列表
        key_bits = []
        for byte in self.key:
            for i in range(7, -1, -1):
                key_bits.append((byte >> i) & 1)
        
        # 应用PC-1置换
        permuted_key = [key_bits[i - 1] for i in pc1]
        
        # 分割为C0和D0
        c = permuted_key[:28]
        d = permuted_key[28:]
        
        # 循环左移
        for _ in range(round_num + 1):
            shift = shifts[_]
            c = c[shift:] + c[:shift]
            d = d[shift:] + d[:shift]
        
        # 合并C和D
        combined = c + d
        
        # 应用PC-2置换
        subkey_bits = [combined[i - 1] for i in pc2]
        
        # 将二进制位列表转换为字节
        subkey_bytes = bytearray()
        for i in range(0, len(subkey_bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(subkey_bits):
                    byte |= subkey_bits[i + j] << (7 - j)
            subkey_bytes.append(byte)
        
        return bytes(subkey_bytes)
    def __init__(self, key):
        try:
            key = bytes.fromhex(key)
        except ValueError:
            raise ValueError("输入的密钥不是有效的十六进制字符串，请输入16位十六进制字符串。")
        if len(key) != 8:
            raise ValueError("密钥长度必须为8字节(16位十六进制)，请输入正确长度的密钥。")
        self.key = key
        # 初始置换表
        self.initial_permutation = [58, 50, 42, 34, 26, 18, 10, 2,
                             60, 52, 44, 36, 28, 20, 12, 4,
                             62, 54, 46, 38, 30, 22, 14, 6,
                             64, 56, 48, 40, 32, 24, 16, 8,
                             57, 49, 41, 33, 25, 17, 9, 1,
                             59, 51, 43, 35, 27, 19, 11, 3,
                             61, 53, 45, 37, 29, 21, 13, 5,
                             63, 55, 47, 39, 31, 23, 15, 7]
        # 最终置换表
        self.final_permutation = [40, 8, 48, 16, 56, 24, 64, 32,
                            39, 7, 47, 15, 55, 23, 63, 31,
                            38, 6, 46, 14, 54, 22, 62, 30,
                            37, 5, 45, 13, 53, 21, 61, 29,
                            36, 4, 44, 12, 52, 20, 60, 28,
                            35, 3, 43, 11, 51, 19, 59, 27,
                            34, 2, 42, 10, 50, 18, 58, 26,
                            33, 1, 41, 9, 49, 17, 57, 25]
        # 扩展置换表
        self.expansion_permutation = [32, 1, 2, 3, 4, 5,
                                4, 5, 6, 7, 8, 9,
                                8, 9, 10, 11, 12, 13,
                                12, 13, 14, 15, 16, 17,
                                16, 17, 18, 19, 20, 21,
                                20, 21, 22, 23, 24, 25,
                                24, 25, 26, 27, 28, 29,
                                28, 29, 30, 31, 32, 1]
        # S盒
        self.s_boxes = [
            # S1
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
             0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
             4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
             15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
            # S2
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
             3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
             0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
             13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
            # S3
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
             13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
             13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
             1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
            # S4
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
             13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
             10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
             3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
            # S5
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
             14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
             4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
             11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
            # S6
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
             10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
             9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
             4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
            # S7
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
             13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
             6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
            # S8
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
             1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
             7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
             2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
        # P置换表
        self.p_permutation = [16, 7, 20, 21,
                        29, 12, 28, 17,
                        1, 15, 23, 26,
                        5, 18, 31, 10,
                        2, 8, 24, 14,
                        32, 27, 3, 9,
                        19, 13, 30, 6,
                        22, 11, 4, 25]

    def encrypt(self, plaintext):
        plaintext = self._pad(plaintext)
        logging.info(f'加密前的明文: {plaintext.hex()}')
        # 初始置换
        plaintext = self._permute(plaintext, self.initial_permutation)
        logging.info(f'填充后的明文: {plaintext.hex()}')
        
        # 16轮Feistel网络
        left, right = plaintext[:4], plaintext[4:]
        for i in range(16):
            new_right = self._feistel(right, self._generate_subkey(i))
            new_right = bytes(a ^ b for a, b in zip(left, new_right))
            left, right = right, new_right
            logging.info(f'第 {i+1} 轮Feistel网络后的结果: {right.hex() + left.hex()}')
        
        # 最终置换
        ciphertext = self._permute(right + left, self.final_permutation)
        logging.info(f'扩展置换后的结果: {ciphertext.hex()}')
        return ciphertext

    def decrypt(self, ciphertext):
        logging.info(f'解密前的密文: {ciphertext.hex()}')
        # 初始置换
        ciphertext = self._permute(ciphertext, self.initial_permutation)
        logging.info(f'填充后的密文: {ciphertext.hex()}')
        
        # 16轮Feistel网络(逆序)
        left, right = ciphertext[:4], ciphertext[4:]
        for i in range(15, -1, -1):
            new_right = self._feistel(right, self._generate_subkey(i))
            new_right = bytes(a ^ b for a, b in zip(left, new_right))
            left, right = right, new_right
            logging.info(f'第 {16 - i} 轮Feistel网络后的结果: {right.hex() + left.hex()}')
        
        # 最终置换
        plaintext = self._permute(right + left, self.final_permutation)
        plaintext = self._unpad(plaintext)
        logging.info(f'最终置换并去除填充后的明文: {plaintext.hex()}')
        return plaintext

    def _pad(self, text):
        pad_len = 8 - (len(text) % 8)
        if pad_len == 0:
            pad_len = 8
        return text + bytes([pad_len] * pad_len)

    def _unpad(self, text):
        if len(text) == 0:
            return text
        try:
            pad_len = text[-1]
            if pad_len < 1 or pad_len > 8:
                return text
            if len(text) >= pad_len and all(b == pad_len for b in text[-pad_len:]):
                return text[:-pad_len]
            return text
        except IndexError:
            return text









# // import unittest

# // 删除原有的测试用例代码
# // class TestDESAlgorithm(unittest.TestCase):
# //     def test_encryption_and_decryption(self):
# //         key = 'FFFFFFFFFFFFFFFF'
# //         plaintext = '1111111111111111'
# //         des = DESAlgorithm(key)
# //         encrypted = des.encrypt(bytes.fromhex(plaintext))
# //         decrypted = des.decrypt(encrypted)
# //         self.assertEqual(decrypted.hex().rstrip('0'), plaintext)
# // 删除原有的测试用例代码
# // if __name__ == '__main__':
# //     unittest.main()
# key = input('请输入16位十六进制密钥: ')
# plaintext = input('请输入十六进制明文: ')
# try:
#     des = DESAlgorithm(key)
#     encrypted = des.encrypt(bytes.fromhex(plaintext))
#     decrypted = des.decrypt(encrypted)
#     print(f'加密结果: {encrypted.hex()}')
#     print(f'解密结果: {decrypted.hex()}')
# except ValueError as e:
#     print(f'输入错误: {e}')

#     unittest.main()








