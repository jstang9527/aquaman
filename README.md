# Aquaman

#### Description：
基于Centos7系统的支持多平台的沙箱环境。可用于仿真各型操作系统，投放样本运行, 结合其他工具流量分析等。例如仿真摄像头、交换机等不同平台操作系统中运行样本，分析恶意流量。

#### Require：
- Centos7.5(>=7.0)
- Python2
- Qemu-4.2.0(>=4.2.0)
- paramiko
- wireshark
- libvirtd
#### Support:
- x86 https://people.debian.org/~aurel32/qemu/i386/debian_wheezy_i386_standard.qcow2
- x86-64 https://people.debian.org/~aurel32/qemu/amd64/debian_wheezy_amd64_standard.qcow2
- arm [https://people.debian.org/~aurel32/qemu/armel/debian_wheezy_armel_standard.qcow2, https://people.debian.org/~aurel32/qemu/armel/initrd.img-3.2.0-4-versatile, https://people.debian.org/~aurel32/qemu/armel/vmlinuz-3.2.0-4-versatile]
- mips [https://people.debian.org/~aurel32/qemu/mips/vmlinux-3.2.0-4-4kc-malta, https://people.debian.org/~aurel32/qemu/mips/debian_wheezy_mips_standard.qcow2]
- mipsel [https://people.debian.org/~aurel32/qemu/mipsel/vmlinux-3.2.0-4-4kc-malta, https://people.debian.org/~aurel32/qemu/mipsel/debian_wheezy_mipsel_standard.qcow2]
#### NetworkScript  
```shell
#! /bin/sh
# Script to bring a network (tap) device for qemu up.
# The idea is to add the tap device to the same bridge
# as we have default routing to.
# in order to be able to find brctl
PATH=$PATH:/sbin:/usr/sbin
ip=$(which ip)
ifconfig=$(which ifconfig)
echo "Starting"  $1
if [ -n "$ip" ]; then
   ip link set "$1" up
else
   brctl=$(which brctl)
   if [ ! "$ip" -o ! "$brctl" ]; then
     echo "W: $0: not doing any bridge processing: neither ip nor brctl utility not found" >&2
     exit 0
   fi
   ifconfig "$1" 0.0.0.0 up
fi
switch=$(ip route ls | \
    awk '/^default / {
          for(i=0;i<NF;i++) { if ($i == "dev") { print $(i+1); next; } }
         }'
        )
    if [ -d /sys/class/net/br0/bridge/. ]; then
        if [ -n "$ip" ]; then
          ip link set "$1" master br0
        else
          brctl addif br0 "$1"
        fi
        exit    # exit with status of the previous command
    fi
echo "W: $0: no bridge for guest interface found" >&2
```  
#### VM Start:
```shell
x86:       
qemu-system-i386 -hda /vm/qemu/x86/1/debian_wheezy_i386_standard.qcow2 -net nic,macaddr=a0:36:9f:a2:32:c2 -net tap -monitor stdio

x86-64:
qemu-system-x86_64 -hda /vm/qemu/x86-64/1/debian_wheezy_amd64_standard.qcow2 -net nic,macaddr=a0:36:9f:a2:32:c3 -net tap -monitor stdio

arm:
qemu-system-arm -M versatilepb -kernel /vm/qemu/arm/1/vmlinuz-3.2.0-4-versatile -initrd /vm/qemu/arm/1/initrd.img-3.2.0-4-versatile -hda /vm/qemu/arm/1/debian_wheezy_armel_standard.qcow2 -append "root=/dev/sda1" -net nic,macaddr=a0:36:9f:a2:32:c4 -net tap -monitor stdio

mips:
qemu-system-mips -M malta -kernel /vm/qemu/mips/1/vmlinux-3.2.0-4-4kc-malta -hda /vm/qemu/mips/1/debian_wheezy_mips_standard.qcow2 -append "root=/dev/sda1 console=tty0" -net nic,macaddr=a0:36:9f:a2:32:c5 -net tap -monitor stdio

mipsel:
qemu-system-mipsel -M malta -kernel /vm/qemu/mipsel/1/vmlinux-3.2.0-4-4kc-malta -hda /vm/qemu/mipsel/1/debian_wheezy_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0" -net nic,macaddr=a0:36:9f:a2:32:c6 -net tap -monitor stdio
```
#### More help:
https://blog.csdn.net/qq_38900565/article/details/103880889