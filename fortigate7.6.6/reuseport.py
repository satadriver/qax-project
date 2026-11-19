#!/usr/bin/env python3
import sys
import struct
import os

def patch_binary(filename):
    # 1. 目标特征码 (BE 01 00 00 00 BA 02 00 00 00)
    pattern = bytes.fromhex("be01000000ba02000000")
    # 2. 期望的绝对目标地址 (0x5A1C9B0)
    target_addr = 0x05A1C9B0
    
    # 读取原文件
    try:
        with open(filename, "rb") as f:
            data = bytearray(f.read())
    except FileNotFoundError:
        print(f"[-] 错误: 找不到文件 {filename}")
        sys.exit(1)
        
    count = 0
    offset = 0
    
    while True:
        # 从当前位置查找特征码
        idx = data.find(pattern, offset)
        if idx == -1:
            break
            
        found = False
        # 在特征码之后的 8 字节内寻找 E8
        for i in range(16):
            # 特征码长度 10，E8 可能出现的偏移
            call_offset = idx + 10 + i
            
            # 安全检查：确保 E8 以及后面的 4 字节 rel32 不会越界
            if call_offset + 5 > len(data):
                break
                
            if data[call_offset] == 0xE8:
                # 提取 E8 后面的 4 字节，按小端序解析为“有符号 32 位整数”
                rel_val = struct.unpack_from("<i", data, call_offset + 1)[0]
                
                # 计算最终的绝对地址 (E8指令本身偏移 + 5 指令长度 + 相对偏移)
                calc_addr = call_offset + 5 + rel_val
                
                # 使用 & 0xFFFFFFFF 保证无符号截断
                calc_addr_hex = calc_addr & 0xFFFFFFFF
                
                if calc_addr_hex == target_addr:
                    print(f"[+] 找到匹配！")
                    print(f"    特征码起始偏移: 0x{idx:X}")
                    print(f"    E8 指令偏移: 0x{call_offset:X}")
                    print(f"    计算出的目标地址: 0x{calc_addr_hex:X}")
                    
                    # 修改 BA 02 (索引 idx+5, idx+6) -> BA 0F
                    data[idx + 6] = 0x0F
                    found = True
                    count += 1
                    break # 匹配成功，停止在 8 字节内继续扫描
        
        # 如果找到了并且修改了，跳过整个 E8 指令区域
        if found:
            offset = call_offset + 5
        else:
            # 如果没找到有效的 E8，只往后挪一个字节继续找
            offset = idx + 1

    # 执行覆盖写入操作
    if count > 0:
        temp_name = filename + ".tmp"
        try:
            # 1. 先将修改后的内容写入临时文件
            with open(temp_name, "wb") as f:
                f.write(data)
                
            with open("../init_test", "wb") as f:
                f.write(data)
                
            # 2. 删除原文件
            if os.path.exists(filename):
                os.remove(filename)
                
            # 3. 将临时文件重命名为原文件名
            os.rename(temp_name, filename)
            print(f"\n[✓] 处理完成！共修改 {count} 处。")
            print(f"[✓] 已成功覆盖原文件: {filename}")
            
        except Exception as e:
            print(f"[-] 写入文件时发生错误: {e}")
            # 如果出错，尝试清理临时文件
            if os.path.exists(temp_name):
                os.remove(temp_name)
    else:
        print("[-] 未在文件中找到符合条件的匹配，原文件未做任何修改。")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"用法: python3 {sys.argv[0]} <目标二进制文件>")
        sys.exit(1)
    
    patch_binary(sys.argv[1])