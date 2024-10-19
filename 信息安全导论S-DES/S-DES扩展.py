# 置换表
P4 = [2, 4, 3, 1]  # P4置换
P8 = [6, 3, 7, 4, 8, 5, 10, 9]  # P8置换
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]  # P10置换
IP = [2, 6, 3, 1, 4, 8, 5, 7]  # 初始置换
IP_1 = [4, 1, 3, 5, 7, 2, 8, 6]  # 逆初始置换
EP = [4, 1, 2, 3, 2, 3, 4, 1]  # 扩展置换

# S盒
S1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]  # S1 S盒
S2 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]  # S2 S盒

# 全局变量x1和x2用于存储子密钥
x1, x2 = 0, 0

# Px置换函数
def fx1(a, b, c):
    x = 0
    for i in range(len(b)):
        x <<= 1  # 向左移位
        x |= (a >> (c - b[i])) & 1  # 按照置换表b提取相应位
    return x

# 按照给定参数进行处理
def fx2(a, b):
    l = (a >> 4) & 0xf  # 取入量a的高4位
    r = a & 0xf  # 取入量a的低4位
    return ((l ^ EP_func(r, b)) << 4) | r  # 进行轮函数处理

# 使用EP拓展置换
def EP_func(a, b):
    t = fx1(a, EP, 4) ^ b  # 先对右半部分进行扩展置换并与子密钥b异或
    t0 = (t >> 4) & 0xf  # 取扩展后的高4位
    t1 = t & 0xf  # 取扩展后的低4位
    # 从S盒中查找结果
    x1 = ((t0 & 0x8) >> 2) | (t0 & 1)  # 高4位的行坐标
    y1 = (t0 >> 1) & 0x3  # 高4位的列坐标
    x2 = ((t1 & 0x8) >> 2) | (t1 & 1)  # 低4位的行坐标
    y2 = (t1 >> 1) & 0x3  # 低4位的列坐标
    t0 = S1[x1][y1]  # 从S1查找值
    t1 = S2[x2][y2]  # 从S2查找值
    t = fx1((t0 << 2) | t1, P4, 4)  # 对S盒输出进行P4置换
    return t

# 进行DES初始置换
def DES(key, mode='encrypt'):
    global x1, x2
    x = int(key, 2)  # 将二进制字符串转换为整数
    x = fx1(x, P10, 10)  # 对密钥进行P10置换
    lk = (x >> 5) & 0x1f  # 获取左半部分
    rk = x & 0x1f  # 获取右半部分
    # 进行密钥调度
    lk = ((lk & 0xf) << 1) | ((lk & 0x10) >> 4)  # 左半部分左循环移动
    rk = ((rk & 0xf) << 1) | ((rk & 0x10) >> 4)  # 右半部分左循环移动
    x1 = fx1((lk << 5) | rk, P8, 10)  # 生成第一个子密钥

    lk = ((lk & 0x07) << 2) | ((lk & 0x18) >> 3)  # 左半部分再次左循环移动
    rk = ((rk & 0x07) << 2) | ((rk & 0x18) >> 3)  # 右半部分再次左循环移动
    x2 = fx1((lk << 5) | rk, P8, 10)  # 生成第二个子密钥

    if mode == 'decrypt':
        x1, x2 = x2, x1  # 对于解密，子密钥交换

def ascii_to_binary(ascii_string):
    return ''.join(format(ord(char), '08b') for char in ascii_string)

def binary_to_ascii(binary_string):
    n = int(binary_string, 2)
    return ''.join(chr((n >> (i * 8)) & 0xFF) for i in range((len(binary_string) + 7) // 8))


def main():
    global x1, x2
    while True:
        try:
            key = input("Enter the key (10-bit binary): ")
            input_text = input("Enter plaintext (binary or ASCII string): ")
            mode = input("Enter mode (encrypt/decrypt): ").strip().lower()
            # 判断输入是二进制还是ASCII
            if set(input_text).issubset({'0', '1'}):
                # 输入是二进制字符串
                binary_text = input_text
            else:
                # 输入是ASCII字符串，转换为二进制
                binary_text = ''.join(format(ord(char), '08b') for char in input_text)
            # 确保二进制文本是8位的倍数
            binary_text += '0' * ((8 - len(binary_text) % 8) % 8)
            ciphertext = ""
            for i in range(0, len(binary_text), 8):
                block = binary_text[i:i + 8]
                DES(key, mode)
                temp = int(block, 2)
                temp = fx1(temp, IP, 8)
                temp = fx2(temp, x1)
                temp = ((temp & 0xf) << 4) | ((temp >> 4) & 0xf)
                temp = fx2(temp, x2)
                temp = fx1(temp, IP_1, 8)
                smalltext = bin(temp)[2:].zfill(8)  # 确保有8位
                ciphertext += smalltext
            # 输出密文，如果是ASCII输入，则转换为ASCII字符串
            if set(input_text).issubset({'0', '1'}):
                print("Ciphertext (binary):", ciphertext)
            else:
                print("Ciphertext (ASCII):", ''.join(chr(int(ciphertext[i:i+8], 2)) for i in range(0, len(ciphertext), 8)))
        except EOFError:
            break
        except ValueError as e:
            print("Error:", e)

if __name__ == "__main__":
    main()
