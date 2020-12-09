airodump : airodump.o
	g++ -o airodump airodump.o -lpcap -lpthread

airodump.o : airodump.cpp

clean : 
	rm -f airodump
	rm -f *.o
