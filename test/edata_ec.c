
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kirk_engine.h"
#include "ecdsa.h"

/*************************************************************/

typedef struct {
	u8 r[20];
	u8 s[20];
	u8 e[20];
}SIGN_INFO;

#include "edata.h"

u8 pubkey_edat_x[20] = {0x1F,0x07,0x2B,0xCC,0xC1,0x62,0xF2,0xCF,0xAE,0xA0,0xE7,0xF4,0xCD,0xFD,0x9C,0xAE,0xC6,0xC4,0x55,0x21};
u8 pubkey_edat_y[20] = {0x53,0x01,0xF4,0xE3,0x70,0xC3,0xED,0xE2,0xD4,0xF5,0xDB,0xC3,0xA7,0xDE,0x8C,0xAA,0xE8,0xAD,0x5B,0x7D};

/*************************************************************/

u8 psp_N[20] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xB5,0xAE,0x3C,0x52,0x3E,0x63,0x94,0x4F,0x21,0x27};
u8 psp_m[20];
u8 psp_k[20];
u8 psp_r[20];

extern ECDSA_PARAM ecdsa_app;

/*************************************************************/

int main(int argc, char *argv[])
{
	SIGN_INFO sig0, sig1, sig2;
	u8 nr[20], ns[20];
	int retv;

	printf("EDATA ID: %s\n", ed0+0x10);

	SHA1(ed0, 0x58, sig0.e);
	memcpy(sig0.r, ed0+0x58, 20);
	memcpy(sig0.s, ed0+0x6c, 20);

	SHA1(ed1, 0x58, sig1.e);
	memcpy(sig1.r, ed1+0x58, 20);
	memcpy(sig1.s, ed1+0x6c, 20);

	SHA1(ed2, 0x58, sig2.e);
	memcpy(sig2.r, ed2+0x58, 20);
	memcpy(sig2.s, ed2+0x6c, 20);

	memcpy(psp_r, sig0.r, 20);


	ecdsa_find_m_k(sig0.r, sig0.s, sig0.e, sig1.s, sig1.e, psp_N, psp_m, psp_k);
	ecdsa_find_m_k(sig0.r, sig0.s, sig0.e, sig2.s, sig2.e, psp_N, psp_m, psp_k);
	ecdsa_find_m_k(sig0.r, sig1.s, sig1.e, sig2.s, sig2.e, psp_N, psp_m, psp_k);

	printf("====================================\n");
	bn_dump("orig r", sig0.r, 20);
	bn_dump("orig s", sig0.s, 20);

	/* ECDSA sign use fixed param */
	ecdsa_set_N(psp_N);
	ecdsa_set_priv(psp_k);
	ecdsa_sign_fixed(sig0.e, psp_m, psp_r, ns);
	printf("ECDSA sign use fixed param:\n");
	bn_dump("sign s", ns, 20);


	/* ECDSA sign test */
	ecdsa_set_curve(&ecdsa_app);
	ecdsa_set_priv(psp_k);
	ecdsa_sign(sig0.e, nr, ns, psp_m);
	printf("ECDSA sign use full param:\n");
	bn_dump("new r", nr, 20);
	bn_dump("new s", ns, 20);

	/* ECDSA verify test */
	ecdsa_set_pub(pubkey_edat_x, pubkey_edat_y);
	retv = ecdsa_verify(sig0.e, sig0.r, sig0.s);
	if(retv==0)
		printf("ECDSA verify passed!\n");
	else
		printf("ECDSA verify failed!\n");

	printf("\n");
	return 0;
}

