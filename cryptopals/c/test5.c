#include <stdio.h>
#include "mylib.h"

int main()
{
	char input[] = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal";

	char key[] = "ICE";
	int keySize = strlen(key);

	int length = strlen(input);

	char* repeatedKey = malloc( sizeof(char)*length +1);

	// populate key string
	int i = length / keySize;

	for(; i<length ;i++)
	{
		strcat(repeatedKey,key);
	}

	repeatedKey[length] = '\0';

	// printf("strlen(input) : %d , strlen(repeatedKey) : %d , i : %d \n", length, strlen(repeatedKey), length/keySize);

	char* xored = stringXOR(StringToHex(input),StringToHex(repeatedKey));

	printf("\n%s\n",xored);

	free(repeatedKey);
	repeatedKey = NULL;


	return 1;
}
