all: pbproxy

pbproxy: pbproxy.c
	gcc server.c myclient.c pbproxy.c -o pbproxy -lcrypto

clean:
	rm -f pbproxy
