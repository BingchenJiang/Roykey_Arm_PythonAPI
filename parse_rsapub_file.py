import os
import binascii


def parse_rsapub_file(file_path):
    """
    自动解析 .Rsapub 二进制公钥文件，
    返回可以直接用于代码的 EXPONENT_HEX 和 MODULUS_HEX
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"找不到公钥文件: {file_path}")

    with open(file_path, 'rb') as f:
        data = f.read()

    # 飞天的公钥结构体大小至少为 264 字节
    if len(data) < 264:
        raise ValueError("公钥文件格式不正确或文件已损坏！")

    # 1. 提取前 4 个字节计算密钥位数 (小端序)
    bits = int.from_bytes(data[0:4], byteorder='little')
    modulus_length = bits // 8  # 例如 1024位 -> 128字节，2048位 -> 256字节

    # 2. 提取第 5 到 8 字节计算公钥指数 E (小端序)
    # 转为整数后，再转为 16 进制字符串（去掉 '0x' 头并变成大写）
    e_int = int.from_bytes(data[4:8], byteorder='little')
    exponent_hex = hex(e_int)[2:].upper()  # 结果通常是 '10001'

    # 3. 截取真正的模数 N 数据块 (从第 9 个字节开始)
    n_bytes = data[8: 8 + modulus_length]
    # 直接将截取出来的字节数组转化为大写的 16 进制字符串
    modulus_hex = binascii.hexlify(n_bytes).decode('utf-8').upper()

    return exponent_hex, modulus_hex


EXPONENT_HEX, MODULUS_HEX = parse_rsapub_file('    ')  # < 填你的公钥.Rsapub
print(EXPONENT_HEX, MODULUS_HEX)

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def build_pem(n, e):
    pub_numbers = rsa.RSAPublicNumbers(e, n)
    pub_key = pub_numbers.public_key()

    pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


# 假设你已经解析出：
n = int.from_bytes(bytes.fromhex(MODULUS_HEX), byteorder='little')

e = int(EXPONENT_HEX, 16)

pem = build_pem(n, e)

print(pem.decode())
