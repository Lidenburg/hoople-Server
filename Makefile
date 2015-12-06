all:
	gcc server.c -o server -Wall -lssl -lcrypto -pthread

clean:
	rm server
