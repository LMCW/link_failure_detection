objects = main.o trie.o hash_table.o rtt.o pcap.o prefix.o
 
pcaptest : $(objects)
	gcc -o pcaptest  $(objects)

main.o: main.c
hash_table.o: hash_table.c
rtt.o: rtt.c
pcap.o: pcap.c
prefix.o: prefix.c
trie.o: trie.c

 
.PHONY : clean
clean :
	rm pcaptest  $(objects)