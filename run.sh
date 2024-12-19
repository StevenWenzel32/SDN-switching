g++ sdnswitch.cpp sdndriver.cpp -o switch
valgrind --leak-check=yes ./switch
./switch
