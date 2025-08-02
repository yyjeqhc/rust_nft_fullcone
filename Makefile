KERNELDIR ?= /lib/modules/$(shell uname -r)/build

#为非系统内核编译模块
# KERNELDIR ?= /root/micro/linux
PWD := $(shell pwd)

obj-m := fullcone.o
obj-m += rcone.o
obj-m += prcone.o

all:
	# 构建 Rust 项目
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	# 清理内核构建产物
	make -C $(KERNELDIR) M=$(PWD) clean