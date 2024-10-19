import time
from concurrent.futures import ThreadPoolExecutor
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

# 暴力破解函数
def brute_force_des(ciphertext, known_plaintext, num_workers=4):
    start_time = time.time()
    print(f"Starting brute force with {num_workers} workers...")
    keys_per_worker = (2 ** 56) // num_workers
    found_key = None

    def check_key(key):
        nonlocal found_key
        decrypted_text = DES(key, mode='decrypt')
        if decrypted_text == known_plaintext:
            found_key = key
            print(f"Found key: {key}")
            print(f"Time taken: {time.time() - start_time} seconds")
            return True
        return False

    def brute_force_worker(start_key, end_key):
        for key in range(start_key, end_key):
            key_str = format(key, '056b')
            if check_key(key_str):
                return

    # 使用线程池来并行化密钥空间的搜索
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        for i in range(num_workers):
            start_key = i * keys_per_worker
            end_key = (i + 1) * keys_per_worker if i < num_workers - 1 else (2 ** 56)
            futures.append(executor.submit(brute_force_worker, start_key, end_key))

        for future in futures:
            future.result()  # 等待所有线程完成

    if found_key is None:
        print("No key found within the search space.")

# 已知密文和明文
known_ciphertext = '10101010'  # 例子密文
known_plaintext = '11001000'  # 例子明文

# 进行暴力破解
brute_force_des(known_ciphertext, known_plaintext)
