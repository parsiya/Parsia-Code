#include <stdio.h>
#include "mylib.h"

int main()
{
	char nem[] = "Hallo Hallo Hallo";
	char* hexed = StringToHex(nem);
	char* unhexed = HexToString(hexed);

	printf("\nOriginal: %s\nHexed: %s\nUnhexed: %s",nem,hexed,unhexed);	

	return 1;
}
