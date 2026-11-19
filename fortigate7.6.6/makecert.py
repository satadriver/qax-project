
import sys
import hashlib
import os

'''
KEY_TABLE_A1A0 = bytes.fromhex(
    "66581c15b457bef27a6fd26038bc563f7589c21d77ed94419b909921f109576c"
    "f79e5f3de5ce7e02ae0e12c83467b533267b073e9ad72151ed91c8c19c41b5f5"
    "2b72f70e74353a93f4b00a00fa85887fa99a19c3cbe44dd97b277e15b0c17d33"
    "61d82e3f4cba7864af06238586da5b1c8347b5f7f05ec1e14a20e25b734ae24a"
    "5e8e2cfe48c7ee0f4468ba788be0793a4e5d97d12b99768bdf29ff2890942411"
    "faec0cc3a1ed21f77509896be4618aecabab4e18082cd4a2fd73fb220d44f905"
    "2a688472f044b7d3760ea3e00055486bd3dbc369238eae6b488752aa9e06cf50"
    "5a737c3040819925b7aeafdac8a783bc94029213fe37a5f809a17c4ffbafc408"
    "21e2991154549e8ecdcef085c6c1"
)
'''

KEY_TABLE_A2C0 = bytes.fromhex(
    "56da1d1fb6d5bff37accf384c6c0bcd2734e8eb25894c0d8ddf4f1695b41956c"
)

# 1. 读取 pub.der 的前 270 字节
with open("pub.der", "rb") as fin:
    size = os.path.getsize("pub.der")
    print(f"文件大小: {size} 字节")
    fin.seek(24)
    raw = fin.read()

if len(raw) < 270:
    raise ValueError("pub.der 长度不足 270 字节")

# 2. 与密钥表循环异或
material = bytearray(270)
for i in range(270):
    material[i] = raw[i] ^ KEY_TABLE_A2C0[i & 0x1F]

# 3. 打印十六进制
for i in range(0, len(material), 16):
    chunk = material[i:i+16]
    hex_str = ' '.join(f'{b:02X}' for b in chunk)
    print(f'{i:04X}: {hex_str}')

# 4. 写入结果文件
with open("pubcert", "wb") as fout:
    fout.write(material)
    