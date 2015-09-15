run: run.o scheme.o benchmark.o Omega.o AO.o PV.o
	gcc -g -o $@ $^ -lcrypto

clean:
	rm -rf *.o run

