UNAME := $(shell uname)

.PHONY : build
build :
ifeq ($(UNAME), Linux)
	gcc -g -Wall -Wextra -Wl,--as-needed `pkg-config --cflags gtk+-3.0 openssl` \
	    -o gccrypt lib/bytes.c lib/debug.c ccrypt.c io.c gtkutils.c gui.c main.c \
	    `pkg-config --libs gtk+-3.0 openssl`
else
endif

.PHONY : clean
clean :
	rm gccrypt
