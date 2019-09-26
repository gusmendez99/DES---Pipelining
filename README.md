# DES

## Description

DES algorithm implementation with pipelining, pthreads and conditional variables.

### Executing program

* How to run the program
```
$ ./g++ des-pipeline.cpp -o des -lpthread
$ ./des -e text.txt crypt.cry keys.txt
$ ./des -d crypt.cry text.txt keys.txt
```

Commands:
* -e: encrypt
* -d: decrypt

## Authors
* Gustavo Mendez
* Roberto Figueroa

## License
This project is licensed under the MIT License
