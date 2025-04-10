import tkinter as tk
from tkinter import filedialog
from des_file_encryption_decryption import encrypt_file, decrypt_file

# 创建主窗口
root = tk.Tk()
root.title("文件加解密工具")
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
root.rowconfigure(1, weight=1)
root.rowconfigure(2, weight=1)
root.rowconfigure(3, weight=1)
root.rowconfigure(4, weight=1)

# 密钥输入框
key_label = tk.Label(root, text="密钥:")
key_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
key_entry = tk.Entry(root)
key_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.EW)

# 输入文件选择按钮
input_file_path = tk.StringVar()


def select_input_file():
    try:
        file_path = filedialog.askopenfilename()
        input_file_path.set(file_path)
        selected_file_label.config(text=f"已选择文件: {file_path}")
        print(f'已选择文件: {file_path}')
    except Exception as e:
        print(f'选择文件时出错: {e}')

input_file_button = tk.Button(root, text="选择输入文件", command=select_input_file)
input_file_button.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky=tk.EW)

# 显示选择的文件标签
selected_file_label = tk.Label(root, text="已选择文件: ")
selected_file_label.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)

# 加密按钮

def perform_encryption():
    key = key_entry.get()
    input_file = input_file_path.get()
    if key and input_file:
        encrypt_file(key, input_file)

encrypt_button = tk.Button(root, text="加密文件", command=perform_encryption)
encrypt_button.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky=tk.EW)

# 解密按钮

def perform_decryption():
    key = key_entry.get()
    input_file = input_file_path.get()
    if key and input_file:
        decrypt_file(key, input_file)

decrypt_button = tk.Button(root, text="解密文件", command=perform_decryption)
decrypt_button.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky=tk.EW)

# 运行主循环
root.mainloop()