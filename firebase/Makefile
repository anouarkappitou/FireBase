module_name = firebase
obj-m += $(module_name).o

$(module_name)-objs = ./src/firebase.o ./src/rulechecker.o ./src/cmd_parser.o

all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
