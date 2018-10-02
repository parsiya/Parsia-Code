#include "mylib.h"

int main()
{
	char buf1[] = "1c0111001f010100061a024b53535009181c";
	char buf2[] = "686974207468652062756c6c277320657965";

	int i=0;

	char* output = 	stringXOR( buf1, buf2 );

	printf("String in Hex : %s\n",output);

	printf("Decoded from Hex: %s",HexToString(output));

	free(output);
	output=NULL;

	return 1;
}
