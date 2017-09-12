#include "stdafx.h"
#include<stdio.h>
#include <string>   
#include <iomanip>  
#include <iostream>   
#include <openssl/md5.h>  
#include <openssl/ssl.h>  
#include<openssl/bn.h>


#define ECDH_SIZE 67  
#define MALLOC_SIZE 0x400u

#pragma warning(disable:4996)

using namespace std;

/*hex转bin*/
int String2Buffer(unsigned char* src, int srclen, unsigned char* dest) {
	int i = 0;
	if (srclen % 2 != 0) return 0;
	for (i = 0; i < srclen / 2; i++)
	{
		char tmp[3];
		tmp[0] = *(src + 2 * i);
		tmp[1] = *(src + 2 * i + 1);
		tmp[2] = 0;
		int out = 0;
		sscanf(tmp, "%x", &out);
		unsigned char ch = (unsigned char)out;
		*(dest + i) = ch;
	}
	return i;
}
/*bin转hex*/
int Buffer2String(unsigned char* src, int srclen, unsigned char* dest) {
	int i;
	for (i = 0; i < srclen; i++)
	{
		char tmp[3] = { 0 };
		sprintf(tmp, "%x", *(src + i));
		if (strlen(tmp) == 1) {
			strcat((char*)dest, "0");
			strncat((char*)dest, tmp, 1);
		}
		else if (strlen(tmp) == 2) {
			strncat((char*)dest, tmp, 2);
		}
		else {
			strcat((char*)dest, "00");
		}
	}
	return i * 2;
}
/*16进制展示数据*/
static void display(const char *tripstr, const char *src, const int src_size)
{
	int i = 0;
	if (tripstr != NULL) {
		printf("%s", tripstr);
	}
	unsigned char*tmp = (unsigned char*)malloc(MALLOC_SIZE);
	memset(tmp, 0, MALLOC_SIZE);
	Buffer2String((unsigned char*)src, src_size, tmp);
	cout << tmp << endl;
	free(tmp);
}

static int Gen_ECDH_Key(string *s1, string *publickey, string *privatekey, string *sharedkey) {
	string str1 = *s1;
	string str2 = *publickey;
	string str3 = *privatekey;

	bool isNeed23 = false;//是否需要第2 3个参数

	if (str1.length() == 0) {
		//第一个参数不能空
		printf("第一个参数不能空\n");
		return -0x10;
	}
	if (isNeed23) {
		//检测第23个参数
		if (str2.length() == 0) {
			printf("str2 null\n");
			return -0x12;
		}
		if (str3.length() == 0) {
			printf("str3 null\n");
			return -0x13;
		}
	}
	EC_KEY *eckey = EC_KEY_new();
	eckey = EC_KEY_new_by_curve_name(NID_secp192k1);//711
	if (!eckey) {
		printf("eckey null\n");
		return -0x7;
	}
	if (str3.length() > 0) {
		//str3不为空
		printf("private key!=null gen sharekey\n");
		BIGNUM *big = BN_new();
		unsigned char *sout3 = (unsigned char*)malloc(MALLOC_SIZE);
		memset(sout3, 0, MALLOC_SIZE);
		int len3 = String2Buffer((unsigned char*)str3.c_str(), str3.length(), sout3);
		BN_mpi2bn(sout3, len3, big);
		if (!big) {
			printf("big null");
			return -0x5;
		}
		char *p = BN_bn2hex(big);
		if (p)
		{
			printf("set prikey is 0x%s\n", p);
			OPENSSL_free(p);//释放p
			free(sout3);//释放 sout3
		}
		int r = EC_KEY_set_private_key(eckey, big);
		printf("r=%d\n", r);
		BN_free(big);//释放
		if (r != 1) {
			printf("EC_KEY_set_private_key Failed~\n");
			return -0x1;
		}
		const EC_GROUP *group = EC_KEY_get0_group(eckey);
		EC_POINT *point = EC_POINT_new(group);
		if (str2.length() > 0) {
			unsigned char *str2bin = (unsigned char*)malloc(MALLOC_SIZE);
			memset(str2bin, 0, MALLOC_SIZE);
			int len22 = String2Buffer((unsigned char*)str2.c_str(), str2.length(), str2bin);
			int r1 = EC_POINT_oct2point(group, point, str2bin, len22, NULL);
			free(str2bin);
			if (r1 != 1) {
				printf("set pubkey EC_POINT_oct2point Failed~");
				return -0x11;
			}
		}
		else
		{
			int r2 = EC_POINT_mul(group, point, NULL, NULL, NULL, NULL);
			if (r2 != 1) {
				printf("r2 failed=%d\n", r2);
				return -0x2;
			}
		}

		int r3 = EC_KEY_set_public_key(eckey, point);
		if (r3 != 1) {
			printf("set pubkeyfailed ret=%d\n", r3);
			return -0x3;
		}
	}
	else
	{
		printf("private key==null gen all key\n");
		int r5 = EC_KEY_generate_key(eckey);
		if (r5 != 1) {
			printf("genkey failed%d\n", r5);
			return -0x55;
		}
	}
	const EC_GROUP *group1 = EC_KEY_get0_group(eckey);
	const EC_POINT *point1 = EC_KEY_get0_public_key(eckey);
	//get pubkey
	unsigned char *pubkey = (unsigned char*)malloc(MALLOC_SIZE);
	memset(pubkey, 0, MALLOC_SIZE);
	int publen = EC_POINT_point2oct(group1, point1, POINT_CONVERSION_COMPRESSED, pubkey, ECDH_SIZE, NULL);
	printf("pubkey len=%d\n", publen);
	display("pubkey:", (char*)pubkey, publen);

	unsigned char*pubhex = (unsigned char*)malloc(MALLOC_SIZE);
	memset(pubhex, 0, MALLOC_SIZE);
	Buffer2String(pubkey, publen, pubhex);

	*publickey = (char*)pubhex;//返回pubk
	free(pubkey);//释放pubkey
	free(pubhex);

	//get privatekey
	const BIGNUM *pribig = EC_KEY_get0_private_key(eckey);
	unsigned char *pout = (unsigned char*)malloc(MALLOC_SIZE);
	memset(pout, 0, MALLOC_SIZE);
	int lenpri = BN_bn2mpi(pribig, pout);
	display("prik:", (char*)pout, lenpri);
	unsigned char*ppout = (unsigned char*)malloc(MALLOC_SIZE);
	memset(ppout, 0, MALLOC_SIZE);
	Buffer2String(pout, lenpri, ppout);
	*privatekey = (char*)ppout;//返回prik
	free(pout);
	free(ppout);


	//set str1
	unsigned char *str1bin = (unsigned char*)malloc(MALLOC_SIZE);
	memset(str1bin, 0, MALLOC_SIZE);
	int len11 = String2Buffer((unsigned char*)str1.c_str(), str1.length(), str1bin);
	EC_POINT *point2 = EC_POINT_new(group1);
	int r4 = EC_POINT_oct2point(group1, point2, str1bin, len11, NULL);
	free(str1bin);//释放str1bin
	if (r4 != 1) {
		printf("r4 failed=%d\n", r4);
		return -0x4;
	}
	//get sharedkey
	unsigned char *shared = (unsigned char *)malloc(MALLOC_SIZE);
	memset(shared, 0, MALLOC_SIZE);
	int len = ECDH_compute_key(shared, 512, point2, eckey, NULL);
	printf("share len:%d\n", len);
	if (len <= 0) {
		printf("gen sharedk failed");
		return -0x9;
	}
	unsigned char md5share[MD5_DIGEST_LENGTH];
	MD5(shared, len, md5share);
	display("sharekey:", (char*)md5share, MD5_DIGEST_LENGTH);

	unsigned  char* sharehex = (unsigned char*)malloc(MALLOC_SIZE);
	memset(sharehex, 0, MALLOC_SIZE);
	Buffer2String(md5share, MD5_DIGEST_LENGTH, sharehex);

	*sharedkey = (char*)sharehex;//返回sharekey
	free(shared);//释放shaedkey
	free(sharehex);
	EC_KEY_free(eckey);//释放eckey
	return 1;
}



int main()
{
	string s1 = "020e14a939661cadbdaa0b177b6e8d2b067c310bdeadc09804";
	string pubkey = "021348bccdb2621c2a302bf4d6bbb349c907509b8fd527bd75";
	string prikey = "000000187eaed20dd5d153ed2b0e93bf695f5c6700fd87cbd150a85f";
	string sharekey = "";

	if (Gen_ECDH_Key(&s1, &pubkey, &prikey, &sharekey) != 1) {
		cout << "get shared key failed" << endl;
		return 0;
	}
	/*
	通过hook数据 以上几个参数最后计算的sharekey为:2FF60FFDD54A4DEAB26D0A85E8B9573D
	验证通过算法ok
	*/
	cout << endl << "根据 pubkey prik计算sharek" << endl;
	cout << "pubkey len=" << pubkey.length() / 2 << ":" << pubkey << endl;
	cout << "prikey len=" << prikey.length() / 2 << ":" << prikey << endl;
	cout << "sharekey len=" << sharekey.length() / 2 << ":" << sharekey << endl << endl;


	string s1_gen = "04928D8850673088B343264E0C6BACB8496D697799F37211DEB25BB73906CB089FEA9639B4E0260498B51A992D50813DA8";
	string pubkey_gen = "";
	string prikey_gen = "";
	string sharekey_gen = "";

	if (Gen_ECDH_Key(&s1_gen, &pubkey_gen, &prikey_gen, &sharekey_gen) != 1) {
		cout << "gen all key failed" << endl;
		return 0;
	}
	cout << endl << "生成 pubk prik sharek" << endl;
	cout << "pubkey len=" << pubkey_gen.length() / 2 << ":" << pubkey_gen << endl;
	cout << "prikey len=" << prikey_gen.length() / 2 << ":" << prikey_gen << endl;
	cout << "sharekey len=" << sharekey_gen.length() / 2 << ":" << sharekey_gen << endl << endl;

	cin.get();
	return 0;
}



