CC := gcc
CFLAGS := -std=c11 -Wall -Wextra -Werror

.PHONY: all
all: chall

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

chall: chall.o
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	$(RM) *.o chall
