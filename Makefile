all: btcsteg

clean:
	rm -f btcsteg

btcsteg: btcsteg.cpp
	$(CXX) -g -W -Wall -o $@ $^ -lcryptopp -lscrypt
