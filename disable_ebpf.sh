git checkout tags/mongodb-4.4.0
./autogen.sh
./configure
make -j6
sudo make install

