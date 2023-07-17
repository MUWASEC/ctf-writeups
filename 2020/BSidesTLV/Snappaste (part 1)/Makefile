all:
	gcc -g -c -std=c99 zlib/*.c  
	g++ -g -c -std=c++14 snappaste.cc   
	g++ -g -o snappaste *.o -pthread

clean:
	rm *.o snappaste