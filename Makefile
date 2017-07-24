CFLAGS = -O2
ITERS = 1000

all: testp256 test25519

testp256: testp256.c
	$(CC) $(CFLAGS) -o $@ testp256.c -lcrypto

test25519: curve25519.c spake25519.c
	$(CC) $(CFLAGS) -o $@ curve25519.c spake25519.c -lcrypto

clean:
	$(RM) *.o testp256 test25519
