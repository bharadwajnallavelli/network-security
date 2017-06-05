#!/bin/bash 
make clean; make
rm -Rf user1 user2 stest 
mkdir user1 user2 stest
cp pictstor  user1
cp pictstor  user2
cp pictstord stest
cp ../testfiles/plaintext.txt user1/plaintext.txt
cp ../testfiles/faq.pdf user1/faq.pdf
cp ../testfiles/ducks.jpg user1/ducks.jpg

mkdir stest/data
cp ../data/server_cert.pem stest/data
cp ../data/server.pem stest/data
cp ../data/CA_cert.pem stest/data
cp ../data/authorized.txt stest/data
cp ../data/dh_params.pem stest/data

mkdir user1/data
cp ../data/user1_cert.pem user1/data/user_cert.pem
cp ../data/user1.pem user1/data/user.pem
cp ../data/CA_cert.pem user1/data/CA_cert.pem
cp run_tests.sh user1

mkdir user2/data
cp ../data/user2_cert.pem user2/data/user_cert.pem
cp ../data/user2.pem user2/data/user.pem
cp ../data/CA_cert.pem user2/data/CA_cert.pem
