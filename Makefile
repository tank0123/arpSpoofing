all : arpSpoofing

arpSpoofing: arpSpoofing.o
	g++ -g -o arpSpoofing arpSpoofing -lpcap -pthread

arpSpoofing.o:
	g++ -g -c -o arpSpoofing.o arpSpoofing.cpp

clean:
	rm -f arpSpoofing
	rm -f *.o

