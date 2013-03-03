	.set noreorder

#include "pspstub.s"

	STUB_START	"scePspNpDrm_driver",0x00090011,0x00030005
	STUB_FUNC	0x04618D16,sceNpDrmGetIDps
	STUB_FUNC	0x0F9547E6,sceNpDrmGetVersionKey
	STUB_FUNC	0x00AD67F8,sceNpDrmGetFixedKey
	STUB_END

