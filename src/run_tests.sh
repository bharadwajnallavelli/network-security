#!/bin/bash 

#
## Function definitions
# 

printUsage() {
    echo "  "    
    echo "USAGE: $0 [ PORT ]"
    echo "   Runs the functional tests"
    echo "   PORT defaults to 5610"
    echo "  "    
   exit 1
} 

#
## Manage options before start
# 

if [ $# -gt 1 ]; then 
	echo "ERROR: Too many arguments" 
	printUsage
else if [ $# -eq 1 ]; then 
			PORT=$1            
		else 
			PORT=5610
	fi
fi


echo "INFO: Functional Tests START"  

Executed=0
Passed=0
Failed=0

MY_USER=$(basename $PWD)

echo "INFO: This is user: $MY_USER"

echo "INFO: Test PUT"
./pictstor localhost $PORT <<STDIN 
put plaintext.txt 
put faq.pdf
put ducks.jpg 
quit 
STDIN

for i in plaintext.txt faq.pdf ducks.jpg 
do 
	echo "INFO: PUT $i" 
	if [[ -s ../stest/file_store/${MY_USER}/$i ]] &&  $( diff ./$i ../stest/file_store/${MY_USER}/$i ) ; then
		echo "PUT $i: Passed"
        Passed=$(expr $Passed + 1) 
	else 	
		echo "PUT $i: Failed"
        Failed=$(expr $Failed + 1) 
	fi
	Executed=$(expr $Executed + 1) 
	echo "------------------------------------------------------------------------------"	
	rm -f $i 
done	

echo "INFO: Test LS"
./pictstor localhost $PORT ls
echo "------------------------------------------------------------------------------"	
	
echo "INFO: Test GET"
./pictstor localhost $PORT <<STDIN 
get plaintext.txt 
get faq.pdf
get ducks.jpg 
quit 
STDIN
	
echo "------------------------------------------------------------------------------"	

for i in plaintext.txt faq.pdf ducks.jpg 
do
    echo "INFO: GET $i" 
    ./pictstor localhost $PORT get $i
    if [[ -s ./$i ]] &&  $( diff ./$i ../stest/file_store/${MY_USER}/$i ) ; then
	echo "GET $i: Passed"
        Passed=$(expr $Passed + 1) 
    else     
        Failed=$(expr $Failed + 1) 
    fi	
    Executed=$(expr $Executed + 1) 
    echo "INFO: Verfiy $i after get. Expected to succeed."
    if  ./pictstor localhost $PORT verify $i | grep "File verified"  ; then
	echo "Verfiy $i: Passed"
        Passed=$(expr $Passed + 1) 
    else
        Failed=$(expr $Failed + 1) 
    fi	
    Executed=$(expr $Executed + 1) 
    echo "------------------------------------------------------------------------------"	
    rm -f ../stest/$i 	
done
echo "------------------------------------------------------------------------------"	
echo "Tests Executed: $Executed"
echo "Tests Passed:   $Passed"
echo "Tests Failed:   $Failed"

exit $Failed 
