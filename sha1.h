#pragma once
#ifndef SHA1_H_INCLUDED
#define SHA1_H_INCLUDED
#define N 1000000

#define F1(B,C,D) ((B&C) | (~B&D))
#define F2(B,C,D) (B^C^D)
#define F3(B,C,D) ((B&C) | (B&D) | (C&D))
#define F4(B,C,D) (B^C^D)

#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6

typedef unsigned char   UChar;
UChar HexToAscii(unsigned int c);
int chartoword(unsigned char* Originaltext, int start);
void divide(unsigned char* Originaltext, int* group, int length);
void Getw(unsigned int w[], unsigned int group[], int llong);
unsigned int Step(unsigned int w[], int t);


#endif 