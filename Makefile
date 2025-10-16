# --- Compiler setup ---
CC = gcc
CFLAGS = -Wall -pedantic -Wextra -Isrc -Iexternal/tiny-AES-c
SRC = src/aes_kw.c external/tiny-AES-c/aes.c
TESTS = tests/test_kw.c
BIN_DIR = bin

# --- Targets ---
all: build

build: $(BIN_DIR)/libaes_kw.a

$(BIN_DIR)/libaes_kw.a: $(SRC)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -c $(SRC)
	ar rcs $(BIN_DIR)/libaes_kw.a *.o
	rm -f *.o

test:
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/test_kw $(SRC) $(TESTS)
	./$(BIN_DIR)/test_kw

clean:
	rm -rf $(BIN_DIR) *.o

.PHONY: all build test clean
