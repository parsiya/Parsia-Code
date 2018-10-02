#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
 
//Encode - Decode Base64 Taken from the interwebz
/* Usage :
 char* base64EncodeOutput;
 Base64Encode("Hello World", &base64EncodeOutput);
 printf("Output (base64): %s\n", base64EncodeOutput);
 
 //Decode From Base64
 char* base64DecodeOutput;
 Base64Decode("SGVsbG8gV29ybGQ=", &base64DecodeOutput);
 printf("Output: %s\n", base64DecodeOutput);
*/

int Base64Encode(const char* message, char** buffer) 
{ //Encodes a string to base64

	BIO *bio, *b64;
	// size_t size;
	FILE* stream;
	int encodedSize = 4*ceil((double)strlen(message)/3);
	*buffer = (char *)malloc(encodedSize+1);
 
	stream = fmemopen(*buffer, encodedSize+1, "w");
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stream, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, message, strlen(message));
	BIO_flush(bio);
	BIO_free_all(bio);
	fclose(stream);
 
	return (0); //success
}

//Decodes Base64

int calcDecodeLength(const char* b64input) 
{ //Calculates the length of a decoded base64 string

	int len = strlen(b64input);
	int padding = 0;
 
	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
	padding = 2;
	else if (b64input[len-1] == '=') //last char is =
	padding = 1;
 
	return (int)len*0.75 - padding;
}
 
int Base64Decode(char* b64message, char** buffer) 
{ //Decodes a base64 encoded string

	BIO *bio, *b64;
	int decodeLen = calcDecodeLength(b64message),
	len = 0;
	*buffer = (char*)malloc(decodeLen+1);
	FILE* stream = fmemopen(b64message, strlen(b64message), "r");
 
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stream, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	len = BIO_read(bio, *buffer, strlen(b64message));

	if (len != decodeLen) return 0;

	//Can test here if len == decodeLen - if not, then return an error
	(*buffer)[len] = '\0';
 
	BIO_free_all(bio);
	fclose(stream);
 
	return len; // return the length of the decoded string in case it has NULL bytes in it
}

/*********************************************************/
/*					Muh Own Kreationz */
// Convert from Hex to char to feed into base64

// takes two digits of hex as input and return corresponding ascii character

char HexToChar(char firstDigit, char secondDigit)
{
	char inp[3];
	inp[0] = firstDigit;
	inp[1] = secondDigit;
	inp[2] ='\0';	// null terminating the array

	int num;
	sscanf(inp, "%x", &num);

	return (char) num;
}

// same as above, returns int

int HexToInt(char firstDigit, char secondDigit)
{
	char inp[3];
	inp[0] = firstDigit;
	inp[1] = secondDigit;
	inp[2] ='\0';	// null terminating the array

	int num;
	sscanf(inp, "%x", &num);

	return num;
}

// Converts a hex character to its integer value
// e.g. hex a will return char 10.
char fromHex(char ch)
{
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

// Converts an integer value to its hex character
char toHex(char code) 
{
	static char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

// gets a hex encoded string and decodes it
char* HexToString(char *input)
{
	char* hexString =  malloc(sizeof(char)*(strlen(input)/2)+1);
	int i=0;

	for(i=0; i<strlen(input) ; i+=2)	hexString[i/2] = (char) HexToInt(input[i],input[i+1]);

	hexString[strlen(input)/2] = '\0';	// null terminating

	return hexString;
}


char* StringToHex(char *input)
{
	// each string character is converted into two hex chars
	char* hexEncoded = malloc(2*(sizeof(char)*strlen(input))+1);

	int i=0;

	for(i=0; i<strlen(input) ; i++)
	{
		sprintf(&hexEncoded[2*i], "%x", input[i]);
	}

	hexEncoded[2*i] = '\0';	// null terminating the string
	return hexEncoded;

}


/* Hex to Base64 - Remember to free output in caller
   returns 0 for failure and 1 for success
   usage:
   char* output;
   HexToBase64(bem,&output);

   printf("%s\n",output);

   free(output);	// don't forget to free the resource
   output = NULL;

*/
int HexToBase64(char* input, char** output)
{
	char* hexString =  HexToString(input);

	Base64Encode(hexString,output);

	free(hexString);
	hexString = NULL;

	return 1;
}

int Base64ToHex(char* input, char** output)
{
	char* base64DecodeOutput;
	int decodedLength = Base64Decode(input, &base64DecodeOutput),
	i=0;

	if (decodedLength == 0)	return 0;

	(*output) = malloc(sizeof(char)*decodedLength+1);

	for(i=0; i<decodedLength ;i++)	(*output)[i] = toHex(base64DecodeOutput[i]);

	(*output)[decodedLength] = '\0';
	
	return decodedLength;	// return the length of the decoded string
}




/*
	Returns the XOR of two Hex strings of equal length
	Returns NULL if lengths are not equal or 0

*/
char* stringXOR (char* str1, char* str2)
{
	if ( ( strlen(str1) != strlen(str2) ) || (strlen(str1) == 0) || (strlen(str2) == 0) ) return NULL; 	// failure
	
	char* output = malloc( sizeof(char)*strlen(str1)+1);	

	int i=0;
	for (i=0; i<strlen(str1) ;i++)
	{
		output[i] = toHex(fromHex(str1[i]) ^ fromHex(str2[i]));
	}

	output[i] = '\0';

	return output;
}

/*
	Returns an array containing the frequency of each letter
	Capital letters will be counted towards small, the rest will be counted as themselves
	input : string, char *
	output : int* array[255] containing the frequency of each letter

	usage:
	char input[] = "Some String";
	int* frequency = letterfrequency(input);

	now letters will be from frequency[97] to frequency[122] inclusive.
	numbers will be from frequency[48] to frequency[57].
	total number of letters (not including anything else) will be in frequency[0].
	
*/

int* letterfrequency (char* input)
{
	int length = strlen(input);
	int i=0,count=0;

	int* frequency = malloc(sizeof(int)*255);

	for(i=0; i<length ;i++)
	{
		char temp = input[i];
		if ((temp>64)&&(temp<91))	temp +=32; // convert uppercase into lowercase

		frequency[temp] +=1;
	}

	// calculating the totla number of letters
	for(i=97; i<=122 ; i++)		count+=frequency[i];

	frequency[0] = count;
	
	return frequency;

}


/*
	Calculated letter frequency of the string and returns a score stating if it is English or not
	Larger Score means it is probably not English. Lower is better.
*/

float isitEnglish(char* input)
{
	// percentage of letters in English, taken from somewhere on the interwebz
	float englishFreq[26] = {8.04, 1.54, 3.06, 3.99, 12.51, 2.3, 1.96, 5.49, 7.26, 0.16, 0.67, 4.14, 2.53, 7.09, 7.6, 2.0, 0.11, 6.12, 6.54, 9.25, 2.71, 0.99, 1.92, 0.19, 1.73, 0.09};

	float percents[26];		// will hold letter frequency percentage
	int* frequency = letterfrequency(input);

	int i=0;
	float score=0;	// score will be distance of each letter percentage from the index. so lower is better
	
	for(i=0; i<26 ; i++)
	{
		percents[i]= (float) 100* frequency[i+97] / frequency[0] ;	// because 'a' frequency is at index 97

		score += fabs(percents[i] - englishFreq[i]);	// calculate the distance		
	}
	
	//free resources
	free(frequency);
	frequency = NULL;

	return score;
}
