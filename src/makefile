# Name:    Bhavi Dhingra
# RollNo.: 2018201058

CC = g++
CFLAGS = -Wall -std=c++1z -g
DEPS = includes.h common.h
OBJ = common.o main.o
%.o: %.cpp $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

bhavi-mini-torrent: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto -lssl

clean:
	rm -f *.o
