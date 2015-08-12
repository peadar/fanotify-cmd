CXXFLAGS += -g -O0 -std=c++11

fm: fm.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

