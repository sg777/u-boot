
#ifndef USE_HOSTCC
#include <common.h>
#include <fdtdec.h>
#include <asm/types.h>
#include <asm/byteorder.h>
#include <linux/errno.h>
#include <asm/types.h>
#include <asm/unaligned.h>
#include <dm.h>
#else
#include "fdt_host.h"
//#include "mkimage.h"
#include <fdt_support.h>
#endif

#include <u-boot/ecc.h>


int ecc_verify(struct image_sign_info *info,
	       const struct image_region region[], int region_count,
	       uint8_t *sig, uint sig_len)
{

    return 0;
}
