LDFLAGS = -lgcrypt
CXXFLAGS = -std=c++11 -Wall -Wextra -g

cryptogator: cryptogator.o
	$(CXX) -o cryptogator cryptogator.o -I.

clean:
	rm -f *.o cryptogator
