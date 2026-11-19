#!/usr/bin/env python3
"""
FortiGate rootfs.gz 加密脚本 V2 - 支持外部 RSA 密钥

相比 V1 版本的改进：
1. 支持从外部文件导入 RSA 私钥（PEM 格式）
2. 支持从外部文件导入 RSA 公钥（PEM 或 BER 格式）
3. 保持自动生成密钥的功能作为默认选项
4. 增强的密钥验证和错误处理
5. 直接输出可替换 decrypt_rootfs.py KEY_TABLE_A1A0 的混淆表

加密流程（与 encrypt_rootfs.py 一致，decrypt_rootfs.py 的逆过程）:
1. 生成或导入 RSA 密钥对（需 2048 位）
2. 生成随机 RC4 key
3. 使用 RC4 变种加密 rootfs.gz
4. 计算加密后数据的 SHA256 hash
5. 构造256字节签名消息：00||01||FF*157||00||hash||unused||rc4_key
6. 使用 RSA 私钥签名，并用公钥自检
7. 使用 ChaCha20 加密 RSA 公钥
8. 生成 KEY_TABLE_A1A0 替换表：A1A0[i] = DER[i] ^ A2C0[i & 0x1F]
9. 将加密数据和签名拼接
"""

import sys
import hashlib
import os
import argparse
from chacha20_custom import chacha20_encrypt
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

# 与 decrypt_rootfs.py / 内核 byte_8179A2C0 一致的 32 字节循环 XOR 表
# 内核去混淆方式: DER[i] = A1A0[i] ^ A2C0[i & 0x1F]
KEY_TABLE_A2C0 = bytes.fromhex(
    "56da1d1fb6d5bff37accf384c6c0bcd2734e8eb25894c0d8ddf4f1695b41956c"
)


def sha256_hash(data):
    """计算SHA256哈希"""
    return hashlib.sha256(data).digest()


def derive_chacha20_key_nonce(initial_key_hex):
    """从初始key派生ChaCha20的key和nonce"""
    initial_key = bytes.fromhex(initial_key_hex)

    # 派生key：SHA256(key[3:32] + key[0:3])
    key_input = initial_key[3:32] + initial_key[0:3]
    derived_key = sha256_hash(key_input)

    # 派生nonce：SHA256(key[1:32] + key[0:1])，取前16字节
    nonce_input = initial_key[1:32] + initial_key[0:1]
    derived_nonce_full = sha256_hash(nonce_input)
    derived_nonce = derived_nonce_full[:16]

    return derived_key, derived_nonce


def load_rsa_private_key(key_file):
    """
    从文件加载 RSA 私钥

    支持的格式：
    - PEM 格式（PKCS#1 或 PKCS#8）
    - DER 格式
    """
    print(f"[*] 从文件加载 RSA 私钥: {key_file}")

    if not os.path.exists(key_file):
        raise FileNotFoundError(f"私钥文件不存在: {key_file}")

    with open(key_file, 'rb') as f:
        key_data = f.read()

    try:
        # 尝试导入私钥
        rsa_key = RSA.import_key(key_data)

        # 验证是否包含私钥
        if not rsa_key.has_private():
            raise ValueError("加载的密钥不包含私钥部分")

        print(f"[+] RSA 私钥加载成功")
        print(f"[+] 密钥大小: {rsa_key.size_in_bits()} 位")
        print(f"[+] 模数 n: {hex(rsa_key.n)[:66]}...")
        print(f"[+] 公钥指数 e: {hex(rsa_key.e)}")

        return rsa_key

    except Exception as e:
        raise ValueError(f"无法加载 RSA 私钥: {e}")


def load_rsa_public_key(key_file):
    """
    从文件加载 RSA 公钥

    支持的格式：
    - PEM 格式
    - DER/BER 格式（270字节）
    """
    print(f"[*] 从文件加载 RSA 公钥: {key_file}")

    if not os.path.exists(key_file):
        raise FileNotFoundError(f"公钥文件不存在: {key_file}")

    with open(key_file, 'rb') as f:
        key_data = f.read()

    try:
        # 尝试作为 PEM 格式导入
        if key_data.startswith(b'-----BEGIN'):
            rsa_key = RSA.import_key(key_data)
            print(f"[+] RSA 公钥加载成功（PEM 格式）")
        else:
            # 尝试作为 BER 格式导入
            from Crypto.Util.asn1 import DerSequence, DerInteger

            # 去除填充的零字节
            key_data = key_data.rstrip(b'\x00')

            # 解析 BER 编码的 RSAPublicKey
            seq = DerSequence()
            seq.decode(key_data)

            if len(seq) != 2:
                raise ValueError("BER 格式公钥结构错误")

            n = DerInteger().decode(seq[0]).value
            e = DerInteger().decode(seq[1]).value

            rsa_key = RSA.construct((n, e))
            print(f"[+] RSA 公钥加载成功（BER 格式）")

        print(f"[+] 密钥大小: {rsa_key.size_in_bits()} 位")
        print(f"[+] 模数 n: {hex(rsa_key.n)[:66]}...")
        print(f"[+] 公钥指数 e: {hex(rsa_key.e)}")

        return rsa_key

    except Exception as e:
        raise ValueError(f"无法加载 RSA 公钥: {e}")


def generate_rsa_keypair(key_size=2048):
    """生成RSA密钥对"""
    print(f"[*] 生成 {key_size} 位 RSA 密钥对...")
    key = RSA.generate(key_size)
    print(f"[+] RSA密钥生成完成")
    print(f"[+] 模数 n: {hex(key.n)[:66]}...")
    print(f"[+] 公钥指数 e: {hex(key.e)}")
    return key


def export_rsa_pubkey_ber(rsa_key):
    """
    导出RSA公钥为BER格式 (270字节)

    需要的格式是 RSAPublicKey (SEQUENCE { n INTEGER, e INTEGER })
    不是 SubjectPublicKeyInfo 格式
    """
    from Crypto.Util.asn1 import DerSequence, DerInteger

    # 手动构造 RSAPublicKey 结构
    # SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    seq = DerSequence()
    seq.append(DerInteger(rsa_key.n).encode())
    seq.append(DerInteger(rsa_key.e).encode())
    pubkey_der = seq.encode()

    # 验证长度
    print(f"[*] RSA公钥编码长度: {len(pubkey_der)} 字节")

    if len(pubkey_der) > 270:
        raise ValueError(f"RSA公钥太大 ({len(pubkey_der)} 字节)，无法填充到270字节")

    # 填充到270字节
    if len(pubkey_der) < 270:
        padding_len = 270 - len(pubkey_der)
        pubkey_der = pubkey_der + (b'\x00' * padding_len)
        print(f"[*] 填充 {padding_len} 字节到270字节")

    return pubkey_der


def build_key_table_a1a0(pubkey_ber):
    """
    由 270 字节 DER 公钥生成可替换 KEY_TABLE_A1A0 的混淆表 (270 字节)

    对应 decrypt_rootfs.py / 内核的去混淆方式:
        DER[i] = A1A0[i] ^ A2C0[i & 0x1F]
    故:  A1A0[i] = DER[i] ^ A2C0[i & 0x1F]
    """
    assert len(pubkey_ber) == 270, "DER 公钥必须为 270 字节"
    assert pubkey_ber[0] == 0x30, "DER 公钥必须以 SEQUENCE (0x30) 开头"

    table = bytes(pubkey_ber[i] ^ KEY_TABLE_A2C0[i & 0x1F] for i in range(270))

    # 自检: 按 decrypt_rootfs.py 的去混淆方式应还原出原 DER
    check = bytes(table[i] ^ KEY_TABLE_A2C0[i & 0x1F] for i in range(270))
    assert check == pubkey_ber, "KEY_TABLE_A1A0 自检失败"
    return table


def rc4_crypt(data, key):
    """
    变种 RC4 加密/解密（加解密同一函数）

    与 decrypt_rootfs.rc4_decrypt 算法完全一致
    （对应内核 rc4_decrypt_initrd @ 0xFFFFFFFF81710334）
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


def build_sign_message(encrypted_data, rc4_key):
    """
    构造 256 字节 PKCS#1 v1.5 签名消息（对应内核 verify_and_decrypt_rootfs）

    格式: 00 || 01 || FF*157 || 00 || SHA256(密文)[32] || unused[32] || rc4_key[32]
    注意: 内核对镜像中加密后的数据计算 SHA-256（解密发生在验签之后），
          因此这里必须哈希密文而非明文。
    """
    assert len(rc4_key) == 32, "RC4 密钥必须为 32 字节"
    digest = sha256_hash(encrypted_data)
    unused = os.urandom(32)   # 内核不校验这段, 任意值均可
    m = b'\x00\x01' + (b'\xff' * 157) + b'\x00' + digest + unused + rc4_key
    assert len(m) == 256, "签名消息长度必须为 256 字节"
    return m


def rsa_private_sign(padded_message, rsa_key):
    """
    使用RSA私钥签名: s = m^d mod n

    输入为已按 PKCS#1 v1.5 填充好的 256 字节消息
    （仅支持 2048 位密钥，与内核签名格式一致）
    """
    n = rsa_key.n
    d = rsa_key.d
    key_size = (rsa_key.size_in_bits() + 7) // 8  # 256 bytes for 2048-bit key

    if key_size != 256:
        raise ValueError(f"内核签名格式需要 2048 位 RSA 密钥, 当前为 {rsa_key.size_in_bits()} 位")

    m = bytes_to_long(padded_message)
    if m >= n:
        raise ValueError("消息过大, 无法签名")

    # RSA签名: s = m^d mod n
    s = pow(m, d, n)

    # 转换回256字节
    signature = long_to_bytes(s, key_size)

    return signature


def self_verify(signature, encrypted_data, plaintext_data, rsa_key):
    """
    用公钥自检（与内核 verify_signature 逻辑一致）:
    验证签名（哈希密文） + 提取 RC4 密钥解密后是否还原明文
    """
    n = rsa_key.n
    e = rsa_key.e

    # m = sig^e mod n
    m = pow(bytes_to_long(signature), e, n)
    m_bytes = long_to_bytes(m, 256)

    digest = sha256_hash(encrypted_data)
    if m_bytes[0] != 0x00 or m_bytes[1] != 0x01:
        return False
    if m_bytes[2:159] != b'\xff' * 157 or m_bytes[159] != 0x00:
        return False
    if m_bytes[160:192] != digest:
        return False

    rc4_key = m_bytes[224:256]
    return rc4_crypt(encrypted_data, rc4_key) == plaintext_data


def encrypt_rootfs(input_file, initial_key_hex, output_file,
                    rsa_private_key_file=None,
                    rsa_public_key_file=None,
                    import_private_key=None,
                    import_public_key=None,
                    encrypted_rsa_pubkey_file=None,
                    encrypted_rsa_pubkey_hex_file=None,
                    key_table_file=None):
    """
    加密FortiGate rootfs.gz文件

    参数:
        input_file: 未加密的rootfs.gz
        initial_key_hex: ChaCha20初始密钥
        output_file: 加密后的输出文件
        rsa_private_key_file: RSA私钥输出文件（当生成新密钥时）
        rsa_public_key_file: RSA公钥输出文件（当生成新密钥时）
        import_private_key: 要导入的RSA私钥文件路径
        import_public_key: 要导入的RSA公钥文件路径
        encrypted_rsa_pubkey_file: 加密的RSA公钥输出文件（二进制格式）
        encrypted_rsa_pubkey_hex_file: 加密的RSA公钥输出文件（十六进制文本格式）
        key_table_file: 可替换 KEY_TABLE_A1A0 的混淆表输出文件（十六进制文本格式）
    """
    print(f"[*] 读取未加密文件: {input_file}")
    with open(input_file, 'rb') as f:
        plaintext_data = f.read()

    print(f"[*] 文件大小: {len(plaintext_data)} 字节")

    # 验证gzip魔数
    if plaintext_data[:2] != b'\x1f\x8b':
        print("[!] 警告: 输入文件不是有效的GZIP格式")

    # 1. 获取或生成RSA密钥对
    print("\n[*] 步骤1: 准备RSA密钥对")

    if import_private_key:
        # 从文件导入私钥
        rsa_key = load_rsa_private_key(import_private_key)

        # 如果同时提供了公钥文件，验证它们是否匹配
        if import_public_key:
            pubkey = load_rsa_public_key(import_public_key)
            if pubkey.n != rsa_key.n or pubkey.e != rsa_key.e:
                raise ValueError("提供的公钥和私钥不匹配")
            print("[+] 公钥和私钥匹配验证通过")

    elif import_public_key:
        raise ValueError("如果只提供公钥，无法进行签名操作。请同时提供私钥。")

    else:
        # 生成新的RSA密钥对
        rsa_key = generate_rsa_keypair(2048)

    # 内核签名格式要求 2048 位 RSA 密钥（256 字节消息/签名）
    if rsa_key.size_in_bits() != 2048:
        raise ValueError(f"内核签名格式需要 2048 位 RSA 密钥, 当前为 {rsa_key.size_in_bits()} 位")

    # 2. 生成随机RC4密钥
    print("\n[*] 步骤2: 生成RC4密钥")
    rc4_key = os.urandom(32)
    print(f"[+] RC4 Key: {rc4_key.hex()}")

    # 3. 使用RC4变种加密
    print("\n[*] 步骤3: 使用RC4变种加密数据")
    encrypted_data = rc4_crypt(plaintext_data, rc4_key)
    print(f"[+] 加密完成: {len(encrypted_data)} 字节")

    # 4. 计算加密后数据的SHA256（内核校验的是密文哈希）
    print("\n[*] 步骤4: 计算密文SHA256哈希")
    data_hash = sha256_hash(encrypted_data)
    print(f"[+] Hash: {data_hash.hex()}")

    # 5. 构造签名消息
    print("\n[*] 步骤5: 构造签名消息 (00||01||FF*157||00||hash||unused||rc4_key)")
    signature_data = build_sign_message(encrypted_data, rc4_key)
    print(f"[+] 签名消息长度: {len(signature_data)} 字节")

    # 6. RSA签名 + 公钥自检
    print("\n[*] 步骤6: 使用RSA私钥签名")
    signature = rsa_private_sign(signature_data, rsa_key)
    print(f"[+] 签名长度: {len(signature)} 字节")
    print(f"[+] 签名: {signature.hex()[:128]}...")

    print("[*] 公钥自检 (验签 + RC4解密还原)")
    if not self_verify(signature, encrypted_data, plaintext_data, rsa_key):
        raise ValueError("自检失败: 签名无效或解密结果与明文不一致")
    print("[+] 自检通过")

    # 7. 导出并加密RSA公钥
    print("\n[*] 步骤7: 导出并加密RSA公钥")
    rsa_pubkey_ber = export_rsa_pubkey_ber(rsa_key)
    print(f"[+] RSA公钥(BER格式): {len(rsa_pubkey_ber)} 字节")
    print(f"[+] 公钥: {rsa_pubkey_ber.hex()[:128]}...")

    # 8. 生成可替换 KEY_TABLE_A1A0 的混淆表 (DER ^ A2C0 循环 XOR)
    print("\n[*] 步骤8: 生成 KEY_TABLE_A1A0 替换表")
    key_table = build_key_table_a1a0(rsa_pubkey_ber)
    print("[+] KEY_TABLE_A1A0 替换表 (270 字节, 可直接粘贴到 decrypt_rootfs.py):")
    key_table_hex = key_table.hex()
    for i in range(0, len(key_table_hex), 64):
        print('    "%s"' % key_table_hex[i:i + 64])

    # 使用ChaCha20加密RSA公钥
    chacha_key, chacha_nonce = derive_chacha20_key_nonce(initial_key_hex)
    encrypted_rsa_pubkey = chacha20_encrypt(chacha_key, chacha_nonce, rsa_pubkey_ber)
    print(f"[+] 加密的RSA公钥: {encrypted_rsa_pubkey.hex()[:128]}...")

    # 9. 拼接最终文件
    print("\n[*] 步骤9: 拼接最终加密文件")
    final_data = encrypted_data + signature
    print(f"[+] 最终文件大小: {len(final_data)} 字节")

    # 10. 保存文件
    print(f"\n[*] 保存加密文件到: {output_file}")
    with open(output_file, 'wb') as f:
        f.write(final_data)

    # 11. 保存RSA私钥（仅当生成新密钥时）
    if not import_private_key and rsa_private_key_file:
        print(f"[*] 保存RSA私钥到: {rsa_private_key_file}")
        with open(rsa_private_key_file, 'w') as f:
            f.write(rsa_key.export_key(format='PEM').decode())

    # 12. 保存RSA公钥（仅当生成新密钥时）
    if not import_private_key and not import_public_key and rsa_public_key_file:
        print(f"[*] 保存RSA公钥到: {rsa_public_key_file}")
        with open(rsa_public_key_file, 'w') as f:
            f.write(rsa_key.publickey().export_key(format='PEM').decode())

    # 13. 保存加密的RSA公钥（二进制格式）
    if encrypted_rsa_pubkey_file:
        print(f"[*] 保存加密的RSA公钥到: {encrypted_rsa_pubkey_file}")
        with open(encrypted_rsa_pubkey_file, 'wb') as f:
            f.write(encrypted_rsa_pubkey)

    # 14. 保存加密的RSA公钥（十六进制文本格式）
    if encrypted_rsa_pubkey_hex_file:
        print(f"[*] 保存加密的RSA公钥（十六进制）到: {encrypted_rsa_pubkey_hex_file}")
        with open(encrypted_rsa_pubkey_hex_file, 'w') as f:
            f.write(encrypted_rsa_pubkey.hex())

    # 15. 保存 KEY_TABLE_A1A0 替换表（十六进制文本格式）
    if key_table_file:
        print(f"[*] 保存 KEY_TABLE_A1A0 替换表到: {key_table_file}")
        with open(key_table_file, 'w') as f:
            f.write(key_table.hex())

    print("\n[+] 加密完成！")
    print(f"\n[*] 输出文件:")
    print(f"    加密文件: {output_file}")
    if not import_private_key and rsa_private_key_file:
        print(f"    RSA私钥: {rsa_private_key_file}")
    if not import_private_key and not import_public_key and rsa_public_key_file:
        print(f"    RSA公钥: {rsa_public_key_file}")
    if encrypted_rsa_pubkey_file:
        print(f"    加密RSA公钥（二进制）: {encrypted_rsa_pubkey_file}")
    if encrypted_rsa_pubkey_hex_file:
        print(f"    加密RSA公钥（十六进制）: {encrypted_rsa_pubkey_hex_file}")
    if key_table_file:
        print(f"    KEY_TABLE_A1A0 替换表: {key_table_file}")

    return True


def main():
    #print ("hello world")
    parser = argparse.ArgumentParser(
        description='FortiGate rootfs.gz 加密工具 V2 - 支持外部 RSA 密钥',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用自动生成的密钥加密
  python encrypt_rootfs_v2.py input.gz f0f3b7... output.gz -o priv.pem -O pub.pem

  # 使用外部私钥加密
  python encrypt_rootfs_v2.py input.gz f0f3b7... output.gz --import-private-key my_private.pem

  # 使用外部公钥和私钥加密
  python encrypt_rootfs_v2.py input.gz f0f3b7... output.gz --import-private-key priv.pem --import-public-key pub.pem

  # 同时保存加密的公钥（二进制格式）
  python encrypt_rootfs_v2.py input.gz f0f3b7... output.gz -o priv.pem -e encrypted_pubkey.bin

  # 保存加密的公钥为十六进制文本
  python encrypt_rootfs_v2.py input.gz f0f3b7... output.gz -o priv.pem -E encrypted_pubkey.txt

  # 同时输出可替换 decrypt_rootfs.py KEY_TABLE_A1A0 的混淆表
  python encrypt_rootfs_v2.py input.gz f0f3b7... output.gz -o priv.pem -t key_table_a1a0.txt
        """
    )

    # 必需参数
    parser.add_argument('input_file',
                        help='未加密的 rootfs.gz 文件路径')
    parser.add_argument('chacha20_key',
                        help='ChaCha20 初始密钥（32字节十六进制）')
    parser.add_argument('output_file',
                        help='加密后的输出文件路径')

    # 密钥导入选项
    key_group = parser.add_argument_group('密钥导入选项')
    key_group.add_argument('--import-private-key', '-i',
                          metavar='FILE',
                          help='导入已有的 RSA 私钥文件（PEM 格式）')
    key_group.add_argument('--import-public-key', '-I',
                          metavar='FILE',
                          help='导入已有的 RSA 公钥文件（PEM 或 BER 格式）')

    # 密钥输出选项
    output_group = parser.add_argument_group('密钥输出选项（生成新密钥时）')
    output_group.add_argument('--output-private-key', '-o',
                             metavar='FILE',
                             help='保存生成的 RSA 私钥文件路径')
    output_group.add_argument('--output-public-key', '-O',
                             metavar='FILE',
                             help='保存生成的 RSA 公钥文件路径（PEM 格式）')

    # 其他选项
    other_group = parser.add_argument_group('其他选项')
    other_group.add_argument('--encrypted-pubkey', '-e',
                            metavar='FILE',
                            help='保存加密的 RSA 公钥文件路径（二进制格式）')
    other_group.add_argument('--encrypted-pubkey-hex', '-E',
                            metavar='FILE',
                            help='保存加密的 RSA 公钥文件路径（十六进制文本格式）')
    other_group.add_argument('--key-table', '-t',
                            metavar='FILE',
                            help='保存可替换 decrypt_rootfs.py KEY_TABLE_A1A0 的混淆表（十六进制文本格式）')

    args = parser.parse_args()
    
    #print ("hello world")

    # 验证密钥参数的逻辑
    if args.import_public_key and not args.import_private_key:
        parser.error("如果使用 --import-public-key，必须同时提供 --import-private-key")

    if args.import_private_key and (args.output_private_key or args.output_public_key):
        print("[!] 警告: 使用外部密钥时，密钥输出选项将被忽略")

    try:
        success = encrypt_rootfs(
            input_file=args.input_file,
            initial_key_hex=args.chacha20_key,
            output_file=args.output_file,
            rsa_private_key_file=args.output_private_key,
            rsa_public_key_file=args.output_public_key,
            import_private_key=args.import_private_key,
            import_public_key=args.import_public_key,
            encrypted_rsa_pubkey_file=args.encrypted_pubkey,
            encrypted_rsa_pubkey_hex_file=args.encrypted_pubkey_hex,
            key_table_file=args.key_table
        )
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n[!] 错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    #print ("hello world")
    main()
