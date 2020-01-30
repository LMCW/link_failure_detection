objects = main.o pcap.o prefix.o
 
pcaptest : $(objects)
	gcc -o pcaptest  $(objects)

main.o: pcap.h prefix.h trie.h
pcap.o: pcap.h
prefix.o: prefix.h
 
.PHONY : clean
clean :
	rm pcaptest  $(objects)