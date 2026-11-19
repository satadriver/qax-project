#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FortiGate (FortiOS 7.6.6) rootfs.gz 完整性校验 + 解密脚本
=========================================================

逆向对象: fortigate_kernel.i64  (x86_64 vmlinux, 非 PIE)

目标函数:
  - verify_and_decrypt_rootfs  @ 0xFFFFFFFF81710480  (initcall, 注册于 .init.data@0xFFFFFFFF817E0BA4)
  - rc4_decrypt_initrd         @ 0xFFFFFFFF81710334

保护方案概述
------------
initrd 镜像布局:  [ 加密的 rootfs.gz ][ 256 字节 RSA 签名块 ]

启动时 (initcall) 依次执行:
  1. 去混淆内嵌 RSA 公钥 (XOR 两张表)  ->  ASN.1 DER (PKCS#1 RSAPublicKey)
  2. 对 rootfs.gz 数据 (不含末尾 256 字节) 计算 SHA-256
  3. m = signature^e mod n   (RSA-2048 公钥运算)
  4. 校验标准 PKCS#1 v1.5 填充 (见 verify_signature):
        m[0]      == 0x00
        m[1]      == 0x01
        m[2:159]  == 0xFF * 157
        m[159]    == 0x00
        m[160:192]== SHA256(rootfs.gz)
  5. 提取 RC4 密钥 = m[224:256] (32 字节)
  6. 用 RC4 变种对 rootfs.gz 原地解密 (XOR)

用法:
  python3 decrypt_rootfs.py <initrd_image> [输出文件]

  initrd_image: 从固件中提取的 initrd (rootfs.gz + 256 字节签名尾部)
  输出文件:     解密后的 rootfs.gz (默认: <输入>.decrypted)
"""

import sys
import hashlib
import pdb

# ---------------------------------------------------------------------------
# 内嵌密钥表 (来自内核 .init.data)
#   byte_8179A1A0  @ 0xFFFFFFFF8179A1A0  (270 字节)
#   byte_8179A2C0  @ 0xFFFFFFFF8179A2C0  (32 字节, 循环 XOR)
# ---------------------------------------------------------------------------
KEY_TABLE_A1A0 = bytes.fromhex(
    "66581c15b457bef27a6fd26038bc563f7589c21d77ed94419b909921f109576c"
    "f79e5f3de5ce7e02ae0e12c83467b533267b073e9ad72151ed91c8c19c41b5f5"
    "2b72f70e74353a93f4b00a00fa85887fa99a19c3cbe44dd97b277e15b0c17d33"
    "61d82e3f4cba7864af06238586da5b1c8347b5f7f05ec1e14a20e25b734ae24a"
    "5e8e2cfe48c7ee0f4468ba788be0793a4e5d97d12b99768bdf29ff2890942411"
    "faec0cc3a1ed21f77509896be4618aecabab4e18082cd4a2fd73fb220d44f905"
    "2a688472f044b7d3760ea3e00055486bd3dbc369238eae6b488752aa9e06cf50"
    "5a737c3040819925b7aeafdac8a783bc94029213fe37a5f809a17c4ffbafc408"
    "21e2991154549e8ecdcef085c6c1")


KEY_TABLE_A2C0 = bytes.fromhex(
    "56da1d1fb6d5bff37accf384c6c0bcd2734e8eb25894c0d8ddf4f1695b41956c"
)


def derive_public_key():
    """去混淆内嵌密钥表并解析 ASN.1 DER, 返回 (n:int, e:int)。"""
    material = bytearray(270)
    for i in range(270):
        material[i] = KEY_TABLE_A1A0[i] ^ KEY_TABLE_A2C0[i & 0x1F]
        
    with open("fortigate7.6.6_cert", "wb") as f:
        f.write(material)

    def read_tlv(data, off):
        tag = data[off]; off += 1
        length = data[off]; off += 1
        if length & 0x80:
            nbytes = length & 0x7F
            length = int.from_bytes(data[off:off + nbytes], "big")
            off += nbytes
        return tag, length, off

    # material = SEQUENCE { INTEGER n, INTEGER e }
    tag, length, body = read_tlv(material, 0)
    assert tag == 0x30, "去混淆结果不是 SEQUENCE, 密钥表可能不匹配"

    values = []
    p = body
    end = body + length
    while p < end:
        t, l, b = read_tlv(material, p)
        assert t == 0x02, "期望 INTEGER"
        v = material[b:b + l]
        if v and v[0] == 0:      # 去掉符号位前缀 0x00
            v = v[1:]
        values.append(v)
        p = b + l

    n_bytes, e_bytes = values[0], values[1]
    return int.from_bytes(n_bytes, "big"), int.from_bytes(e_bytes, "big")


def verify_signature(sig: bytes, data: bytes, n: int, e: int):
    """
    RSA 公钥验证并返回 (valid: bool, rc4_key: bytes)。
    sig : 256 字节签名块
    data: 被签名的原始数据 (加密的 rootfs.gz)
    """
    assert len(sig) == 256, "签名块必须为 256 字节"

    # m = sig^e mod n  (教科书式 RSA, 内嵌公钥为裸 RSA 无 OAEP/PSS)
    m_int = pow(int.from_bytes(sig, "big"), e, n)
    m = m_int.to_bytes(256, "big")   # 大端 256 字节

    digest = hashlib.sha256(data).digest()

    # 标准 PKCS#1 v1.5 填充校验 (对应 verify_and_decrypt_rootfs 0xffffffff81710718 起)
    # 解密后明文 m (256B) = 00 || 01 || FF*157 || 00 || SHA256(data)[32] || unused[32] || RC4_key[32]
    # 注意: 前导 0x00 使 m 的显著字节数为 255, mpi_read_buffer 剥掉该字节后缓冲区整体左移 1 字节,
    #       所以内核里看到的检查对象是缓冲区[0]=m[1]=0x01 而非 m[0]。
    if m[0] != 0x00:
        return False, None
    if m[1] != 0x01:
        return False, None
    if m[2:159] != b"\xff" * 157:
        return False, None
    if m[159] != 0x00:
        return False, None
    if m[160:192] != digest:
        return False, None

    rc4_key = m[224:256]   # 32 字节 RC4 密钥
    return True, rc4_key


def rc4_decrypt(data: bytes, key: bytes):
    """
    变种 RC4 解密 (对应 rc4_decrypt_initrd @ 0xFFFFFFFF81710334)。
    标准 RC4 KSA + 修改过的 PRGA (额外 ^0xAA 查表混合)。
    """
    S = list(range(256))
    j = 0
    # KSA (32 字节密钥, key[i & 0x1F])
    for i in range(256):
        j = (j + S[i] + key[i & 0x1F]) & 0xFF
        S[i], S[j] = S[j], S[i]

    i = 0
    out = bytearray(data)
    for pos in range(len(data)):
        i = (i + 1) & 0xFF
        t = S[i]
        j = (j + t) & 0xFF
        u = S[j]
        S[i] = u
        S[j] = t

        # 修改过的 keystream 生成:
        a = ((j >> 3) ^ (i << 5)) & 0xFF
        b = ((i >> 3) ^ (j << 5)) & 0xFF
        s = (S[a] + S[b]) & 0xFF
        idx = s ^ 0xAA
        v7 = (u + t) & 0xFF                       # = (S[i] + S[j]) 交换后
        v7n = (S[idx] + S[v7]) & 0xFF
        v8 = (j + u) & 0xFF                       # = (j + S[i]) 交换后
        ks = S[v8] ^ v7n

        out[pos] ^= ks
    return bytes(out)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        sys.exit(1)

    image_path = argv[1]
    out_path = argv[2] if len(argv) > 2 else image_path + ".decrypted"
    print("111")
    with open(image_path, "rb") as f:
        image = f.read()

    if len(image) <= 256:
        print("[!] 镜像太小 (<= 256 字节), 不是有效的 initrd")
        sys.exit(1)

    encrypted = image[:-256]     # 加密的 rootfs.gz
    sig = image[-256:]           # RSA 签名块

    n, e = derive_public_key()
    print("[*] RSA 公钥:")
    print("    n (%d bit): %s..." % (n.bit_length(), hex(n)[2:20]))
    print("    e: %d" % e)

    valid, rc4_key = verify_signature(sig, encrypted, n, e)
    if not valid:
        print("[!] 签名校验失败 (完整性校验不通过)")
        sys.exit(2)

    #print("[+] 签名校验通过 (SHA-256 + RSA-2048)")
    
    #print("[*] RC4 密钥: %s" % rc4_key.hex())
    
    decrypted = rc4_decrypt(encrypted, rc4_key)
    print("[*] RC4 解密完成, 输出 %d 字节" % len(decrypted))

    # 可选: 校验 gzip 魔数
    if decrypted[:2] == b"\x1f\x8b":
        print("[+] 解密结果以 gzip 魔数 (0x1f8b) 开头, 看起来正确")
    else:
        print("[!] 解密结果不以 gzip 魔数开头, 请检查 (可能是 cpio/其他格式)")

    with open(out_path, "wb") as f:
        f.write(decrypted)
    print("[+] 已写出: %s" % out_path)


if __name__ =="__mai