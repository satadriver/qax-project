#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import zlib
import sys

def crc32_file(path):
    """计算文件的 CRC32，返回 32 位无符号整数"""
    crc = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            crc = zlib.crc32(chunk, crc)
    return crc & 0xFFFFFFFF


def make_filechecksum(out_path="filechecksum"):
    """
    读取 /mnt/rootfs.gz，生成 filechecksum，格式：
        /rootfs.gz,CRC32,0x<8位小写hex>
        /flatkc,CRC32,0xffffffff
    如果 filechecksum 已存在，直接覆盖。
    """
    rootfs_path = "/mnt/rootfs.gz"

    if not os.path.exists(rootfs_path):
        print(f"错误: 找不到 {rootfs_path}", file=sys.stderr)
        sys.exit(1)

    rootfs_crc = crc32_file(rootfs_path)

    entries = [
        ("/rootfs.gz", rootfs_crc),
        ("/flatkc",    0xFFFFFFFF),
    ]

    # "w" 模式：文件存在则清空覆盖，不存在则创建
    with open(out_path, "w", encoding="ascii", newline="\n") as f:
        for path, crc in entries:
            f.write(f"{path},CRC32,0x{crc:08x}\n")

    print(f"已生成 {out_path}")
    print(f"  /rootfs.gz -> 0x{rootfs_crc:08x}")
    print(f"  /flatkc    -> 0xffffffff")


if __name__ == "__main__":
    make_filechecksum()