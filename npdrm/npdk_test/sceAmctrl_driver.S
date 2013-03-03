	.set noreorder

#include "pspstub.s"

	STUB_START	"sceAmctrl_driver",0x00010011,0x00060005
	STUB_FUNC	0x0785C974,sceDrmBBCipherUpdate
	STUB_FUNC	0x1CCB66D2,sceDrmBBCipherInit
	STUB_FUNC	0x525B8218,sceDrmBBMacInit
	STUB_FUNC	0x58163FBE,sceDrmBBMacUpdate
	STUB_FUNC	0x9951C50F,sceDrmBBCipherFinal
	STUB_FUNC	0xEF95A213,sceDrmBBMacFinal
	STUB_FUNC	0xF5186D8E,sceDrmBBMacFinal2
	STUB_END
