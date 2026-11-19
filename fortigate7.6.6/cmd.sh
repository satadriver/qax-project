#!/bin/bash
#set -euo pipefail


# 检查 zopfli 是否已经安装
if ! command -v zopfli &> /dev/null; then
    echo "zopfli 未安装，正在安装..."
    
    # 更新软件源（可选，但建议在安装前执行）
    sudo apt-get update
    
    # 执行安装，-y 表示自动回答 yes
    sudo apt-get install -y zopfli
    
    # 检查刚才的安装是否成功
    if [ $? -eq 0 ]; then
        echo "zopfli 安装成功！"
    else
        echo "zopfli 安装失败，请检查网络或软件源配置。"
        exit 1
    fi
else
    echo "zopfli 已安装，无需操作。"
fi


# 使用 python -c 尝试导入 Crypto 模块，并屏蔽所有输出
python3 -c "import Crypto" &> /dev/null
# 判断上一条命令的返回值
if [ $? -ne 0 ]; then
    echo "检测到 Crypto 模块未安装，正在使用 pip 安装..."
    
    # 建议安装 pycryptodome，而不是直接叫 crypto 的包
    # 如果你必须装 pycrypto，请将下面替换为 pip install pycrypto
    pip3 install pycryptodome
    
    if [ $? -eq 0 ]; then
        echo "安装成功！"
    else
        echo "安装失败，请检查 pip 或网络配置。"
        exit 1
    fi
else
    echo "Crypto 模块已安装，无需操作。"
fi

echo "duplicate Fort-disk1.vmdk..."
cp ./Fort-disk1-bak.vmdk ./Fort-disk1.vmdk


# 清理旧连接（如果存在）
umount /mnt 2>/dev/null
qemu-nbd --disconnect /dev/nbd1 2>/dev/null
pkill -f qemu-nbd 2>/dev/null
sleep 1

# 加载模块并连接
modprobe nbd max_part=16
qemu-nbd --connect=/dev/nbd1 Fort-disk1.vmdk
sleep 1
partprobe /dev/nbd1 2>/dev/null || true

# 确认分区节点
lsblk /dev/nbd1

sudo fdisk -l /dev/nbd1

# 挂载
mount /dev/nbd1p1 /mnt

chattr -i /mnt/flatkc

chattr -i /mnt/rootfs.gz

chattr -i /mnt/hash_bin.sha256

read -n 1 -s -r -p "Press any key to continue..."
echo

echo "duplicate flatkc and rootfs.gz..."
cp /mnt/flatkc ./
cp /mnt/rootfs.gz ./

echo "extract piggy and vmlinux.gz, part3..."
#凡是带 seek 的写出操作，必须用 bs（或显式 obs=1）；只用 skip+count 的提取操作，写 ibs=1 就够（输出是顺序写新文件，obs 无所谓）。
dd if=flatkc of=piggy ibs=1 skip=$[0] count=$[0x43B1]

dd if=flatkc of=vmlinux.gz ibs=1 skip=$[0x43B1] count=$[0x75E8C9]

dd if=flatkc of=part3 ibs=1 skip=$[0x762C7A] count=$[214502]

echo "decompress vmlinux.gz..."
#gzip -dc vmlinux.gz #this line will cause garbled text on screen
gzip -dc vmlinux.gz > vmlinux

echo "decrypt rootfs.gz..."
python3 decrypt_rootfs.py rootfs.gz rootfs_plain.gz

rm -rf rootfs
mkdir rootfs
cd rootfs

echo "decompress rootfs cpio..."
gzip -dc ../rootfs_plain.gz | cpio -idm

echo "decompress /bin..."
xz -d bin.tar.xz
tar -xf bin.tar

xxd -s $((0x13c507c)) -l 11 ./bin/init
printf '\xeb' | dd of=./bin/init bs=1 seek=$((0x13c507c)) conv=notrunc
xxd -s $((0x13c507c)) -l 11 ./bin/init

echo "revise 0x13C7B60..."
xxd -s $((0x13C7B60)) -l 11 ./bin/init
printf '\xc3' | dd of=./bin/init bs=1 seek=$((0x13C7B60)) conv=notrunc
xxd -s $((0x13C7B60)) -l 11 ./bin/init

echo "revise 0x13C7D90..."
xxd -s $((0x13C7D90)) -l 11 ./bin/init
printf '\xc3' | dd of=./bin/init bs=1 seek=$((0x13C7D90)) conv=notrunc
xxd -s $((0x13C7D90)) -l 11 ./bin/init

echo "revise 0x13C98F0..."
xxd -s $((0x13C98F0)) -l 11 ./bin/init
printf '\xc3' | dd of=./bin/init bs=1 seek=$((0x13C98F0)) conv=notrunc
xxd -s $((0x13C98F0)) -l 11 ./bin/init

echo "revise 0x13C7230..."
xxd -s $((0x13C7230)) -l 11 ./bin/init
printf '\x31\xc0\xc3' | dd of=./bin/init bs=1 seek=$((0x13C7230)) conv=notrunc
xxd -s $((0x13C7230)) -l 11 ./bin/init
#sub_13C7B60	reboot
#sub_13C7230 	return > 0
#sub_13C7D90	shutdown
#sub_13C98F0	reboot
#exit

echo "revise 0x2A944B3..."
xxd -s $((0x2A944B3)) -l 11 ./bin/init
printf '\x0f' | dd of=./bin/init bs=1 seek=$((0x2A944B3)) conv=notrunc
xxd -s $((0x2A944B3)) -l 11 ./bin/init
echo "revise 0x2a938ec..."
xxd -s $((0x2a938ec)) -l 11 ./bin/init
printf '\x0f' | dd of=./bin/init bs=1 seek=$((0x2a938ec)) conv=notrunc
xxd -s $((0x2a938ec)) -l 11 ./bin/init

#echo "revise init bind..."
#python3 ../reuseport.py ./bin/init

echo "insert busybox and backdoor..."
cp ../busybox ./bin
cp ../backdoor ./bin
cp ../gdb ./bin
cp ../gdbserver ./bin
mv ./bin/smartctl ./bin/smartctl_old
cp ../backdoor ./bin/smartctl
cp ../uctest ./bin/uctest

echo "create link of busybox..."
rm ./bin/sh
ln -s  /bin/busybox ./bin/sh

chmod 777 ./bin/sh
chmod 777 ./bin/smartctl
chmod 777  ./bin/busybox
chmod 777 ./bin/backdoor
chmod 777 ./bin/gdb
chmod 777 ./bin/gdbserver
chmod 777 ./bin/uctest
sudo chown -R root:root ./bin/

# 查看 0x1c6 处的 64 字节十六进制和 ASCII 字符
xxd -s $((0x1c6)) -l 64 /mnt/hash_bin.sha256
# 1. 写入固定偏移处的 smartctl 哈希（纯 64 字符，无换行）
HASH=$(sha256sum ./bin/smartctl | awk '{print $1}')
printf "%s" "$HASH" | dd of=/mnt/hash_bin.sha256 bs=1 seek=$((0x1c6)) count=64 conv=notrunc
xxd -s $((0x1c6)) -l 64 /mnt/hash_bin.sha256

xxd -s $((0x39d)) -l 64 /mnt/hash_bin.sha256
HASH=$(sha256sum ./bin/init | awk '{print $1}')
printf "%s" "$HASH" | dd of=/mnt/hash_bin.sha256 bs=1 seek=$((0x39d)) count=64 conv=notrunc
xxd -s $((0x39d)) -l 64 /mnt/hash_bin.sha256

# 查看文件的最后 10 行
tail -n 10 /mnt/hash_bin.sha256
# 2. 追加其他4个文件的哈希和路径到文件末尾
for f in ./bin/sh ./bin/busybox ./bin/backdoor ./bin/gdb ./bin/gdbserver ./bin/uctest; do 
    hash=$(sha256sum "$f" | awk '{print $1}')
    # 把开头的 "./" 去掉，变成 "/bin/sh" 的格式
    clean_path=$(echo "$f" | sed 's|^\.||') 
    # 使用 printf 确保格式精确，并带有换行符
    printf "%s  %s\n" "$hash" "$clean_path"
done | dd of=/mnt/hash_bin.sha256 bs=1 oflag=append conv=notrunc
tail -n 10 /mnt/hash_bin.sha256

echo "compress /bin..."
tar --warning=no-unknown-keyword -cf  bin.tar ./bin
xz -e bin.tar

echo "compress rootfs.gz..."
find . -path './bin' -prune -o -print | cpio -H newc -o > ../rootfs.cpio
cat ../rootfs.cpio | gzip > ../rootfs_cpio.gz
cd ..

echo "encrypt rootfs.gz..."
python3 ./encrypt_rootfs_v2.py rootfs_cpio.gz 1234567890123456789012345678901234567890123456789012345678901234  rootfs_new.gz -o priv.pem -O pub.pem


echo "genenrate RSA public key and private key..."
openssl rsa  -in  priv.pem -out priv.der -outform DER
openssl rsa -pubin  -in pub.pem -out pub.der -outform DER
python3 makecert.py

echo "write public key in vmlinux..."
dd if=pubcert of=vmlinux bs=1 skip=0 count=270 seek=$((0x199A1A0)) conv=notrunc

#python text will recaculate the signature
#printf '\x75' | dd of=vmlinux bs=1 seek=$((0x19107c6)) conv=notrunc

#set {unsigned int}0xffffffff8b3691d9=0x8941c031  
#set {unsigned char}0xffffffff8b3691dd=0xc6
#set {unsigned int}0xffffffff8b3691de=0x90909090
#set {unsigned short}0xffffffff8b3691e2=0x9090

echo "patch flatkc verifying rootfs.gz..."
xxd -s $((0x5691d9)) -l 11 vmlinux
printf '\x31\xc0\x41\x89\xc6\x90\x90\x90\x90\x90\x90' | dd of=vmlinux bs=1 seek=$((0x5691d9)) conv=notrunc
xxd -s $((0x5691d9)) -l 11 vmlinux

xxd -s $((0x567516)) -l 11 vmlinux
printf '\x90\xe9' | dd of=vmlinux bs=1 seek=$((0x567516)) conv=notrunc
xxd -s $((0x567516)) -l 11 vmlinux

echo "compress vmlinux to vmlinux.gz..."
#cat vmlinux| gzip -c -9 > vmlinux_new.gz #gzip compress zip package bigger than zopli
zopfli -c vmlinux > vmlinux_new.gz

vmlinux_new_size=$(stat -c %s vmlinux_new.gz)

echo "文件 vmlinux_new.gz 的大小为: $vmlinux_new_size 字节"

if [ "$vmlinux_new_size" -gt 7727305 ]; then
    echo "错误：文件大小 $vmlinux_new_size 超过 7727305，脚本退出。"
    exit 1
fi

echo "duplicate flatkc..."
cp flatkc flatkc_new

echo "write vmlinux.gz into flatkc..."
dd if=vmlinux_new.gz of=flatkc_new bs=1 skip=$[0] seek=$[0x43B1] count="$vmlinux_new_size" conv=notrunc

echo "revise size of vmlinux.gz in flatkc..."

#762C7A
python3 -c "import struct,os; os.write(1, struct.pack('<I',$vmlinux_new_size))" | dd of=flatkc_new bs=1 seek=$((0x762CAD)) count=4 conv=notrunc

echo "已写入 size=$vmlinux_new_size"
rm -rf /mnt/flatkc
rm -rf /mnt/rootfs.gz

echo "copy flatkc and rootfs.gz..."
cp flatkc_new /mnt/flatkc
cp rootfs_new.gz /mnt/rootfs.gz

python3 filechecksum.py

umount /mnt
qemu-nbd --disconnect /dev/nbd1

echo "process complete!"

