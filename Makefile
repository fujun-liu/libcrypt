LDFLAGS = -lgcrypt
CXXFLAGS = -Wall -Wextra -g
OBJS = cryptogator_helper.o

cryptogator: cryptogator_helper.o
	$(CXX) $(CXXFLAGS) cryptogator.cc $(OBJS) -o cryptogator $(LDFLAGS)

cryptogator_helper.o: cryptogator_helper.cc

clean:
	rm -f *.o cryptogator
