#include "sha1.h"
#include<stdlib.h>
#include<stdio.h>

unsigned long int A = 0x67452301, B = 0xEFCDAB89, C = 0x98BADCFE, D = 0x10325476, E = 0xC3D2E1F0;
unsigned long int A0 = 0x67452301, B0 = 0xEFCDAB89, C0 = 0x98BADCFE, D0 = 0x10325476, E0 = 0xC3D2E1F0;

UChar HexToAscii(unsigned int c) {
	if (c > 9) {
		return (c + 55);
	}
	else {
		return (c + 48);
	}
}

//字节转换
int chartoword(unsigned char* Originaltext, int start)
{
	return((int)((Originaltext[start] & 0x000000ff) << 24) | (int)((Originaltext[start + 1] & 0x000000ff) << 16) | (int)((Originaltext[start + 2] & 0x000000ff) << 8) | (int)((Originaltext[start + 3] & 0x000000ff)));
}

void divide(unsigned char* Originaltext, int* group, int length)
{
	int temp = length / 4, l = length, llong = length / 64 + (length % 64) / 56;
	while (l >= 0)
	{
		if (l / 4)
		{
			for (int j = 0; j < temp; j++, l -= 4)
			{
				group[j] = chartoword(Originaltext, j * 4);
			}
		}
		else
		{
			Originaltext[temp * 4 + (l + 4) % 4] = 0x80;
			for (int j = length + 1; j <= 3 + temp * 4; Originaltext[j] = 0, j++);
			group[temp] = chartoword(Originaltext, temp * 4);
			l -= 4;
		}
	}
	for (int i = temp + 1; i < 15 + 16 * llong; i++)
	{
		group[i] = 0;
	}

}

void Getw(unsigned int w[], unsigned int group[], int llong)
{
	for (int i = 0; i < llong + 1; i++)
	{
		for (int j = 0; j < 16; j++)
		{
			w[i * 80 + j] = group[i * 16 + j];
			//printf("第%2d组明文是0x%08X\n", i * 80 + j + 1, w[i * 80 + j]);   111
		}
		for (int j = 16; j < 80; w[i * 80 + j++] = ((w[i * 80 + j - 3] ^ w[i * 80 + j - 8] ^ w[i * 80 + j - 14] ^ w[i * 80 + j - 16]) << 1) | ((w[i * 80 + j - 3] ^ w[i * 80 + j - 8] ^ w[i * 80 + j - 14] ^ w[i * 80 + j - 16]) >> 31));
			//printf("第%2d组明文是0x%08X\n", i * 80 + j, w[i * 80 + j - 1]);   222
		//printf("第%2d组明文是0x%08X\n", i * 80 + 80, w[i * 80 + 79]);   333
	}
}

unsigned int Step(unsigned int w[], int t)
{
	unsigned int temp = 0;
	int tt = t % 80;
	if (tt == 0 && t != 0)
	{
		A = A + A0;
		A0 = A;
		B = B + B0;
		B0 = B;
		C = C + C0;
		C0 = C;
		D = D + D0;
		D0 = D;
		E = E + E0;
		E0 = E;
	}
	if (tt >= 0 && tt <= 19) temp = ((A << 5) | (A >> 27)) + F1(B, C, D) + E + w[t] + K1;
	else if (tt >= 20 && tt <= 39) temp = ((A << 5) | (A >> 27)) + F2(B, C, D) + E + w[t] + K2;
	else if (tt >= 40 && tt <= 59) temp = ((A << 5) | (A >> 27)) + F3(B, C, D) + E + w[t] + K3;
	else if (tt >= 60 && tt <= 79) temp = ((A << 5) | (A >> 27)) + F4(B, C, D) + E + w[t] + K4;

	E = D; D = C; C = (B << 30) | (B >> 2); B = A; A = temp;
	//printf("第%2d轮加密后的密文是%08X %08X %08X %08X %08X\n", t + 1, A, B, C, D, E);   //444
}

UChar operation_sha1(unsigned char s[], UChar data[])
{
	unsigned int length = 0;
	int xx = 0;
	for (int i = 0; s[i] != 0; i++, length++)
		xx += 8;
	unsigned int llong = length / 64 + (length % 64) / 56;

	unsigned int* group = (int*)malloc(sizeof(int) * 500000);
	unsigned int* w = (int*)malloc(sizeof(int) * 500000);
	group[(llong + 1) * 16 - 1] = xx;
	divide(s, group, length);
	Getw(w, group, llong);

	for (int i = 0; i <= 79 + llong * 80; i++)
	{
		Step(w, i);
	}
	A = A + A0;
	B = B + B0;
	C = C + C0;
	D = D + D0;
	E = E + E0;
	unsigned int S[5] = { A,B,C,D,E };
	unsigned int temp;
	
	int bb = sizeof(S);
	for (int i = 0; i < sizeof(S) / 4; i++) {
		unsigned int aa = S[i];
		temp = (S[i] >> 28) & 0x0000000f;   // 取16进制数高位放到 HexToAscii 函数中转成字符
		*(data + 8 * i) = HexToAscii(temp);
		temp = S[i] & 0x0f000000;   // 取16进制数低位放到 HexToAscii 函数中转成字符
		*(data + i * 8 + 1) = HexToAscii(temp >> 24);
		temp = S[i] & 0x00f00000;
		*(data + i * 8 + 2) = HexToAscii(temp >> 20);
		temp = S[i] & 0x000f0000;
		*(data + i * 8 + 3) = HexToAscii(temp >> 16);
		temp = S[i] & 0x0000f000;
		*(data + i * 8 + 4) = HexToAscii(temp >> 12);
		temp = S[i] & 0x00000f00;
		*(data + i * 8 + 5) = HexToAscii(temp >> 8);
		temp = S[i] & 0x000000f0;
		*(data + i * 8 + 6) = HexToAscii(temp >> 4);
		temp = S[i] & 0x0000000f;
		*(data + i * 8 + 7) = HexToAscii(temp);
	}
	return data;
}