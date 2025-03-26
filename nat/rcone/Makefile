obj-m += rcone.o

rcone-y := nft_ext_rcone.o nf_nat_rcone.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
