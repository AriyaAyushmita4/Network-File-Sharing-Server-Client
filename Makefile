# Makefile for Network File Sharing (Server & Client)

CXX = g++
CXXFLAGS = -std=c++17 -Wall -pthread
LIBS = -lssl -lcrypto

all: server client

server: server.cpp
	$(CXX) $(CXXFLAGS) server.cpp -o server $(LIBS)

client: client.cpp
	$(CXX) $(CXXFLAGS) client.cpp -o client $(LIBS)

clean:
	rm -f server client
