
#ifndef _ECC_H
#define _ECC_H

#include <errno.h>
#include <image.h>

#define ECC256_BYTES	(32)
#define ECC384_BYTES	(48)
#define ECC521_BYTES	(66)

/**
 * sign() - calculate and return signature for given input data
 *
 * @info:	Specifies key and FIT information
 * @data:	Pointer to the input data
 * @data_len:	Data length
 * @sigp:	Set to an allocated buffer holding the signature
 * @sig_len:	Set to length of the calculated hash
 *
 * This computes input data signature according to selected algorithm.
 * Resulting signature value is placed in an allocated buffer, the
 * pointer is returned as *sigp. The length of the calculated
 * signature is returned via the sig_len pointer argument. The caller
 * should free *sigp.
 *
 * @return: 0, on success, -ve on error
 */
int ecc_sign(struct image_sign_info *info,
	     const struct image_region region[],
	     int region_count, uint8_t **sigp, uint *sig_len);

/**
 * add_verify_data() - Add verification information to FDT
 *
 * Add public key information to the FDT node, suitable for
 * verification at run-time. The information added depends on the
 * algorithm being used.
 *
 * @info:	Specifies key and FIT information
 * @keydest:	Destination FDT blob for public key data
 * @return: 0, on success, -ENOSPC if the keydest FDT blob ran out of space,
		other -ve value on error
*/
int ecc_add_verify_data(struct image_sign_info *info, void *keydest);

/**
 * rsa_verify() - Verify a signature against some data
 *
 * Verify a RSA PKCS1.5 signature against an expected hash.
 *
 * @info:	Specifies key and FIT information
 * @data:	Pointer to the input data
 * @data_len:	Data length
 * @sig:	Signature
 * @sig_len:	Number of bytes in signature
 * @return 0 if verified, -ve on error
 */
int ecc_verify(struct image_sign_info *info,
	       const struct image_region region[], int region_count,
	       uint8_t *sig, uint sig_len);

/**
 * add_tkc_data() - Add trusted-key-certificate information to FDT
 *
 * Add Tier-1 public key information to the FDT node, suitable for
 * verification at run-time. The information added depends on the
 * algorithm being used.
 *
 * @info:	Specifies key and FIT information
 * @keydest:	Destination FDT blob for public key data
 * @return: 0, on success, -ENOSPC if the keydest FDT blob ran out of space,
		other -ve value on error
*/
int ecc_add_tkc_data(struct image_sign_info *info, void *keydest);

#endif
