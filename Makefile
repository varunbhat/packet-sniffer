CC              = g++
CFLAGS          = -c -Wall -ggdb -D_GNU_SOURCE
LDFLAGS         = -lpcap 
CXXFLAGS        = -std=c++11 -pthread -ggdb
SOURCES         = sniffer.cc
INCLUDES        = -I.
OBJECTS         = $(SOURCES:.cc=.o)
TARGET          = sniffer

all: $(SOURCES) $(TARGET) $(LDFLAGS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS) $(CXXFLAGS)

.cc.o:
	$(CC) $(CFLAGS)  $(INCLUDES) $< -o $@ 

clean:
	rm -rf $(OBJECTS) $(TARGET)


