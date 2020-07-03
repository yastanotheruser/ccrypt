UNAME := $(shell uname)

.PHONY : build
build :
ifeq ($(UNAME), Linux)
	gcc -g -Wall -Wextra -o gccrypt `pkg-config --cflags gtk+-3.0 openssl` \
	    lib/bytes.c lib/debug.c ccrypt.c io.c gtkutils.c gui.c main.c \
	    `pkg-config --libs gtk+-3.0 openssl`
else
	x86_64-w64-mingw32-gcc \
        -g -Wall -Wextra -o gccrypt.exe \
        `x86_64-w64-mingw32-pkg-config --cflags gtk+-3.0 openssl` \
        lib/bytes.c lib/debug.c ccrypt.c io.c gtkutils.c gui.c main.c \
        `x86_64-w64-mingw32-pkg-config --libs gtk+-3.0 openssl`
endif

.PHONY : clean
clean :
	rm gccrypt
