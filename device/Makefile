CC = gcc
CFLAG = -Wno-deprecated-declarations -lcurl -lconfig -ljson-c

all: attune.c atelic.c attest.c
	$(CC) $(CFLAG) -o ./bin/attune attune.c
	$(CC) $(CFLAG) -o ./bin/atelic atelic.c
	$(CC) $(CFLAG) -o ./bin/attest attest.c

clean:
	rm ./bin/attune ./bin/atelic ./bin/attest
