# obj-m += helloworld.o
ccflags-y = -std=gnu99

obj-m += verto.o

verto-objs := primary_routines/main.o primary_routines/exit.o

all:

	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:

	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean