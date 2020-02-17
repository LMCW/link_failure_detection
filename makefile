CFLAGS += -g
objects = main.o trie.o hash_table.o rtt.o flow.o pcap.o measure.o prefix.o

pcaptest : $(objects)
	gcc $(CFLAGS) -o pcaptest $(objects)

main.o: main.c
hash_table.o: hash_table.c
rtt.o: rtt.c
flow.o: flow.c
pcap.o: pcap.c
measure.o: measure.c
prefix.o: prefix.c
trie.o: trie.c

 
.PHONY : clean
clean :
	rm pcaptest  $(objects)