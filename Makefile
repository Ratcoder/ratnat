objects := $(patsubst %.c,%.o,$(wildcard src/*.c))

ratnat : $(objects) -lsodium
	gcc -o ratnat $(objects) -lsodium

.PHONY : clean install
clean :
	rm ratnat $(objects)

install :
	cp ratnat /usr/local/bin/ratnat