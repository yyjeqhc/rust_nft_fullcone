obj-m += prcone.o

prcone-y := nft_ext_prcone.o nf_nat_prcone.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
