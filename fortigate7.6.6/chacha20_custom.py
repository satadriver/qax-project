# chacha20_custom.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

def chacha20_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    标准 ChaCha20 加密（IETF 变体，12 字节 nonce）。
    参数顺序请根据 encrypt_rootfs_v2.py 的实际调用调整。
    """
    # cryptography 的 ChaCha20 需要 16 字节 nonce：4 字节 counter + 12 字节 nonce
    if len(nonce) == 12:
        full_nonce = b'\x00\x00\x00\x00' + nonce
    elif len(nonce) == 16:
        full_nonce = nonce
    else:
        raise ValueError("nonce 必须是 12 或 16 字节")

    algorithm = algorithms.ChaCha20(key, full_nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()