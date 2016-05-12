CFLAGS = -Wall -Werror -pthread -g
FLG = -lsqlite3 -lcrypto
all: server client chat

server.o: server.c server.h common.h
	gcc $(CFLAGS) -c server.c $(FLG)

server_helper.o: server_helper.c server.h common.h
	gcc $(CFLAGS) -c server_helper.c $(FLG)

client.o: client.c client.h common.h
	gcc $(CFLAGS) -c client.c $(FLG)

chat.o: chat.c common.h
	gcc $(CFLAGS) -c chat.c $(FLG)

common.o: common.h common.c
	gcc $(CFLAGS) -c common.c $(FLG)

sfwrite.o: sfwrite.h sfwrite.c
	gcc $(CFLAGS) -c sfwrite.c $(FLG)

server:	server_helper.o server.o common.o sfwrite.o
	gcc $(CFLAGS) server_helper.o server.o common.o sfwrite.o -o server $(FLG)

client:	client.o common.o sfwrite.o
	gcc $(CFLAGS) client.o common.o sfwrite.o -o client $(FLG)

chat: chat.o common.o sfwrite.o
	gcc $(CFLAGS) chat.o common.o sfwrite.o -o chat $(FLG)

clean:
	rm -f *.o server client chat


