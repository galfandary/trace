CXXFLAGS:=-std=c++11 -O -s -Wall -pedantic
LINK.o:=$(LINK.cc)
.PHONY: all
all: trace
