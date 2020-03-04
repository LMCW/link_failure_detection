CFLAGS += -g
TARGET = pcaptest
# INC = -I./include
SRCS = main.c \
	hash_table.c \
	flow.c \
	pcap.c \
	prefix.c \
	trie.c \
	iat.c \
	timestamp.c \
	probability.c
	
OBJS = $(SRCS:.c=.o) 

$(TARGET):$(OBJS)
	gcc -o $@ $^

clean :
	rm -rf $(TARGET) $(OBJS)

%.o:%.c
	gcc $(CFLAGS) -o $@ -c $<