g++ -o coldnode main.cpp -L. -std=gnu++14 -static -Wall -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -ldatacomponents -lboost_serialization -lboost_wserialization -luv -lcryptopp -I/home/ubuntu/uvw -I/home/ubuntu/cryptopp/cryptopp
