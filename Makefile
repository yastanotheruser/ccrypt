.PHONY : build
build :
	gcc -g -Wall -Wextra -o gccrypt `pkg-config --cflags gtk+-3.0 openssl` \
	    lib/bytes.c lib/debug.c ccrypt.c io.c gtkutils.c gui.c main.c \
	    `pkg-config --libs gtk+-3.0 openssl`

.PHONY : build-mingw32
build-mingw32 :
	export PKG_CONFIG_PATH=/opt/mxe/usr/i686-w64-mingw32.static/lib/pkgconfig; \
	i686-w64-mingw32-gcc -mwindows \
		-g -Wall -Wextra -o gccrypt.exe `i686-w64-mingw32-pkg-config --cflags gtk+-3.0 openssl` \
		lib/bytes.c lib/debug.c ccrypt.c io.c gtkutils.c gui.c main.c \
		-Wl,--allow-multiple-definition -Wl,-Bstatic -pthread \
		`i686-w64-mingw32-pkg-config --static --libs gtk+-3.0 openssl`

.PHONY : clean
clean :
	rm gccrypt
