from des_algorithm import DESAlgorithm
import os


# 加密文件函数
def encrypt_file(key, input_file_path):
    output_file_path = os.path.splitext(input_file_path)[0] + '_encrypted' + os.path.splitext(input_file_path)[1]
    try:
        des = DESAlgorithm(key)
        with open(input_file_path, 'rb') as infile, open(output_file_path, 'wb') as outfile:
            while True:
                chunk = infile.read(8)
                if not chunk:
                    break
                if len(chunk) < 8:
                    chunk = chunk.ljust(8, b'\0')
                encrypted_chunk = des.encrypt(chunk)
                outfile.write(encrypted_chunk)
        print(f'文件加密成功，加密文件保存至: {output_file_path}')
    except Exception as e:
        print(f'文件加密失败: {e}')


# 解密文件函数
def decrypt_file(key, input_file_path):
    output_file_path = os.path.splitext(input_file_path)[0] + '_decrypted' + os.path.splitext(input_file_path)[1]
    try:
        des = DESAlgorithm(key)
        with open(input_file_path, 'rb') as infile, open(output_file_path, 'wb') as outfile:
            while True:
                chunk = infile.read(8)
                if not chunk:
                    break
                decrypted_chunk = des.decrypt(chunk)
                outfile.write(decrypted_chunk.rstrip(b'\0'))
        print(f'文件解密成功，解密文件保存至: {output_file_path}')
    except Exception as e:
        print(f'文件解密失败: {e}')


