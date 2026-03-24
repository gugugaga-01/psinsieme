# MP-PSI


## Installations

### Required libraries
- Boost
- GMP
- NTL
- Miracl

### Building the Project
After cloning project from git,
##### Linux:
1. Install Boost

   ```
   % wget -O boost_1_81_0.tar.gz https://sourceforge.net/projects/boost/files/boost/1.81.0/boost_1_81_0.tar.gz/download
   % tar xzvf boost_1_81_0.tar.gz
   % cd boost_1_81_0/
   % sudo apt-get install build-essential autoconf
   % ./bootstrap.sh --prefix=/usr/
   % ./b2
   % sudo ./b2 install
   ```

2. Install GMP

   ```
   % wget https://gmplib.org/download/gmp/gmp-6.2.1.tar.xz
   % tar -xvf gmp-6.2.1.tar.xz
   % cd gmp-6.2.1
   % ./configure
   % make
   % make check
   % sudo make install
   ```

3. Install NTL

   ```
   % wget https://libntl.org/ntl-11.5.1.tar.gz
   % tar -xvzf ntl-11.5.1.tar.gz
   % cd ntl-11.5.1/src
   % ./configure 
   % make
   % make check
   % sudo make install
   ```

4. Install Miracl

   ```
   % cd thirdparty/linux/miracl/miracl/source/
   % bash linux64
   % cd ../../../miracl/miracl_osmt/source/
   % bash linux64_cpp
   ```

   

5. Install others

   ```
   sudo apt-get install cmake nasm
   ```

   


## Running the code
```
1. clone this repository
2. cd `this repository`
3. install dependencies
4. cmake .
5. make 
6. bash ./tools/run_benchmark.sh 
(or 7.) ./bin/frontend.exe -n 5 -m 11 -p 0 & ./bin/frontend.exe -n 5 -m 11 -p 1 & ./bin/frontend.exe -n 5 -m 11 -p 2 & ./bin/frontend.exe -n 5 -m 11 -p 3 & ./bin/frontend.exe -n 5 -m 11 -p 4 &

```

**Flags:**

    -n		number of parties
    -m		set size		
    -p		party ID
