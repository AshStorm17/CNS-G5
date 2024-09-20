# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++11

# MySQL Connector flags (assuming you installed MySQL Connector C++ properly)
MYSQL_FLAGS = -lmysqlcppconn

# Target executable
TARGET = bank

# Source files
SRCS = bank.cpp

# Header files
HDRS = bank.h

# Object files
OBJS = $(SRCS:.cpp=.o)

# Rule to build the target executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(MYSQL_FLAGS)

# Rule to compile source files into object files
%.o: %.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) -c $<

# Clean up build files
clean:
	rm -f $(OBJS) $(TARGET)
