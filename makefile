
CXX = g++

LDLIBS = -lpcap 


all: deauth-attack

# beacon-flood 타겟 빌드 규칙
deauth-attack: attack_frame.o main.o utils.o
	$(CXX) -o deauth-attack attack_frame.o main.o utils.o $(LDLIBS)

%.o: %.cpp
	$(CXX) -c $<

clean:
	rm -f deauth-attack *.o

