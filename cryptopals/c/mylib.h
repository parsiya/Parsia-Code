#include "mylib.c"
 
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

int Base64Encode(const char* message, char** buffer);

//Decodes Base64
int calcDecodeLength(const char* b64input); 
int Base64Decode(char* b64message, char** buffer);

// takes two digits of hex as input and return corresponding ascii character
char HexToChar(char firstdigit, char seconddigit);
// same as above but returns int
int HexToInt(char firstdigit, char seconddigit);

// convert a single character to and from hex
char fromHex(char ch);
char toHex(char code);

// Converting hex to string and back
char* HexToString(char *input);
char* StringToHex(char *input);

// Hex to Base64 - Remember to free the returned value in caller
int HexToBase64(char* input, char** output);

// XORs two strings of equal length
char* stringXOR (char* str1, char* str2);

// Returns an array that contains the letter frequency of a string
int* letterfrequency (char* input);

// Returns a score, lower means char frequency of input string is closer to English
float isitEnglish(char* input);


