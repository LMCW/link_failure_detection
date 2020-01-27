objects = main.o pcap.o monitor.o prefix.o
 
pcaptest : $(objects)
	gcc -o pcaptest  $(objects)

main.o: pcap.h monitor.h prefix.h trie.h
pcap.o: pcap.h
monitor.o: monitor.h
prefix.o: prefix.h
 
.PHONY : clean
clean :
	rm pcaptest  $(objects)