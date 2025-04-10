import tkinter as tk
from des_algorithm import DESAlgorithm

# 创建主窗口
root = tk.Tk()
root.title("DES加解密工具")

# 使用网格布局管理器
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
root.rowconfigure(1, weight=1)
root.rowconfigure(2, weight=1)
root.rowconfigure(3, weight=1)
root.rowconfigure(4, weight=1)
root.rowconfigure(5, weight=1)
root.rowconfigure(6, weight=1)

# 创建标签和输入框
key_label = tk.Label(root, text="请输入16位十六进制密钥:")
key_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
key_entry = tk.Entry(root)
key_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.EW)

plaintext_label = tk.Label(root, text="请输入十六进制明文:")
plaintext_label.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
plaintext_entry = tk.Entry(root)
plaintext_entry.grid(row=1, column=1, padx=10, pady=5, sticky=tk.EW)

# 加密函数

def encrypt_text():
    key = key_entry.get()
    plaintext = plaintext_entry.get()
    if len(key) != 16 or not all(c in '0123456789abcdefABCDEF' for c in key):
        result_label.config(text="输入错误: 密钥必须是16位十六进制数。")
        return
    try:
        int(plaintext, 16)
    except ValueError:
        result_label.config(text="输入错误: 明文必须是十六进制数。")
        return
    try:
        des = DESAlgorithm(key)
        encrypted = des.encrypt(bytes.fromhex(plaintext))
        result_label.config(text=f"加密结果: {encrypted.hex()}")
    except ValueError as e:
        result_label.config(text=f"输入错误: {e}")

# 解密函数

def decrypt_text():
    key = key_entry.get()
    ciphertext = encrypted_text.get()
    if len(key) != 16 or not all(c in '0123456789abcdefABCDEF' for c in key):
        result_label.config(text="输入错误: 密钥必须是16位十六进制数。")
        return
    try:
        int(ciphertext, 16)
    except ValueError:
        result_label.config(text="输入错误: 密文必须是十六进制数。")
        return
    try:
        des = DESAlgorithm(key)
        decrypted = des.decrypt(bytes.fromhex(ciphertext))
        result_label.config(text=f"解密结果: {decrypted.hex()}")
    except ValueError as e:
        result_label.config(text=f"输入错误: {e}")

# 创建加密按钮
encrypt_button = tk.Button(root, text="加密", command=encrypt_text)
encrypt_button.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky=tk.EW)

# 创建解密按钮
encrypted_text = tk.Entry(root)
encrypted_text.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky=tk.EW)
decrypt_button = tk.Button(root, text="解密", command=decrypt_text)
decrypt_button.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky=tk.EW)

# 创建结果标签
result_label = tk.Label(root, text="")
result_label.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky=tk.EW)

# 复制函数
def copy_to_clipboard(): 
    encrypted_text = result_label.cget("text") 
    if encrypted_text.startswith("加密结果: "): 
        encrypted_text = encrypted_text[5:] 
        root.clipboard_clear() 
        root.clipboard_append(encrypted_text) 

# 创建右键菜单
menu = tk.Menu(root, tearoff=0) 
menu.add_command(label="复制", command=copy_to_clipboard) 

def show_menu(event): 
    menu.post(event.x_root, event.y_root) 

result_label.bind("<Button-3>", show_menu) 

# 运行主循环
root.mainloop()