LDFLAGS = -lgcrypt
CXXFLAGS = -Wall -Wextra -g
OBJS = cryptogator_algorithms.o

cryptogator: $(OBJS)
	$(CXX) $(CXXFLAGS) cryptogator.cc $(OBJS) -o cryptogator $(LDFLAGS)

cryptogator_algorithms.o: cryptogator_algorithms.cc

clean:
	rm -f *.o cryptogator
