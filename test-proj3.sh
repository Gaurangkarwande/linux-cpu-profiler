# test script for project 3

make
sudo insmod perftop.ko
cat /proc/perftop
sudo rmmod perftop.ko
dmesg -e
make clean