run: run.o scheme.o benchmark.o Omega.o AO.o PV.o util.o
	gcc -g -o $@ $^ -lcrypto

clean:
	rm -rf *.o run

