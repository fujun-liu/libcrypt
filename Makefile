LDFLAGS = -lgcrypt
CXXFLAGS = -Wall -Wextra -g
OBJS = cryptogator_algorithms.o

cryptogator: $(OBJS) cryptogator_helper.o
	$(CXX) $(CXXFLAGS) cryptogator.cc $(OBJS) cryptogator_helper.o -o cryptogator $(LDFLAGS)

cryptogator_algorithms.o: cryptogator_helper.o
	$(CXX) -c $(CXXFLAGS) cryptogator_algorithms.cc cryptogator_helper.o $(LDFLAGS)

cryptogator_helper.o: cryptogator_helper.cc

clean:
	rm -f *.o cryptogator
