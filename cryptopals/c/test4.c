#include <stdio.h>
#include "mylib.h"


int main()
{
	char bem[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

	static char hex[] = "0123456789abcdef";

	int key=0;

	float scores[255];
	float lowestScore = 9999;

	char* xored;

	char* winningKey = malloc(sizeof(char)*strlen(bem)+1);
	char* attackKey = malloc(sizeof(char)*strlen(bem)+1);

	int first=0,second=0;

	for(first=0; first <8 ;first++)
		for(second=0; second<16 ;second++)
		{
			char firstDigit  = hex[first];
			char secondDigit = hex[second];
			
			int i=0;
			for(i=0; i<strlen(bem) ;i+=2)
			{
				attackKey[i] = firstDigit;
				attackKey[i+1] = secondDigit;
			}

			attackKey[strlen(bem)]= '\0';
		
			// initializing the score
			scores[key] = 0.0;

			xored = HexToString( stringXOR(bem, attackKey) );

			// calculate the score
			scores[key] = isitEnglish( HexToString( stringXOR(bem, attackKey) ));

			if ( scores[key] < lowestScore )
			{
				lowestScore = scores[key];
				strncpy(winningKey,attackKey,strlen(attackKey)+1);
			}			

		} 

 
	// releasing resources
	// free(attackKey);
	// attackKey = NULL;

	printf("\nWinning Key : %s", winningKey);
	printf("\nWinning Score : %f", lowestScore);
	printf("\nDecrypted Text : %s\n", HexToString( stringXOR(bem, winningKey) ));

	// releasing resources
	// free(xored);
	// xored = NULL;

	// free(winningKey);
	// winningKey = NULL;

	return 1;
}

// 8.04	1.54	3.06	3.99	12.51	2.3	1.96	5.49	7.26	0.16	0.67	4.14	2.53	7.09	7.6	2	0.11	6.12	6.54	9.25	2.71	0.99	1.92	0.19	1.73	0.09

