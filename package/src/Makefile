
CC :=gcc

TARGET=nmap-scan

SOURCES := cjson.c utils.c main.c
OBJECTS := $(SOURCES:.c=.o) 

LDFLAGS += -lm -lconfig -lpthread
IFLAGS += -I.
CFLAGS += -Os -Wall

all: clean $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) -c -o $@ $(LFLAGS) $(IFLAGS) $<

clean:
	rm -f *.o $(TARGET)

.PHONY: clean
