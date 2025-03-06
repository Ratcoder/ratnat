objects := $(patsubst %.c,%.o,$(wildcard src/*.c))

ratnat : $(objects)
	gcc -o ratnat $(objects) -lsodium

.PHONY : clean
clean :
	rm ratnat $(objects)