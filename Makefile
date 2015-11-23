run: run.o scheme.o benchmark.o Omega.o AO.o PV.o util.o ec-omega-full.o ec-omega-xor.o ec-omega-plain.o ec-pv-full.o ec-pv-xor.o ec-ao.o
	gcc -g -o $@ $^ -lcrypto -L/usr/local/lib

%.o: %.c
	gcc -g -c $^

clean:
	rm -rf *.o run

