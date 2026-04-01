CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -masm=intel -Wall -O2 -c \
          -mno-stack-arg-probe -fno-stack-check -fno-stack-protector \
          -fno-builtin -Wno-unused-function -D_WIN64
INCLUDE = -I./include

.PHONY: all clean

all: ksl_lsa

ksl_lsa: | out
	$(CC) $(CFLAGS) $(INCLUDE) -o out/ksl_lsa.o src/ksl_all_in_one_lsa.c
	@echo "[+] Compilado: out/ksl_lsa.o"

out:
	mkdir -p out

clean:
	rm -f out/*.o

