all : send_arp

send_arp: main.o
	gcc -g -o send_arp main.o -lpcap

main.o:
	gcc -g -c -o main.o main.c

clean:
	rm -f send_arp
	rm -f *.o

