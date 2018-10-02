#include <stdio.h>
#include "mylib.h"

int main()
{
	char bem[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

	// function is located in mylib.c - Uses functions that use openssl library to do so
	// coding functions were taken from the interwebz, the hex to char function is mine

	char* output;
	HexToBase64(bem,&output);

	printf("%s\n",output);

	free(output);
	output = NULL;

	return 1;
}



