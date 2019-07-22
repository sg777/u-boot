
#include "mkimage.h"
#include <stdio.h>
#include <string.h>
#include <image.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

static int fdt_add_bignum(void *blob, int noffset, const char *prop_name,
			  BIGNUM *num, int num_bits)
{
    int nwords = num_bits / 32;
    int size;
    uint32_t *buf, *ptr;
    BIGNUM *tmp, *big2, *big32, *big2_32;
    BN_CTX *ctx;
    int ret;

    tmp = BN_new();
    big2 = BN_new();
    big32 = BN_new();
    big2_32 = BN_new();

    /*
     * Note: This code assumes that all of the above succeed, or all fail.
     * In practice memory allocations generally do not fail (unless the
     * process is killed), so it does not seem worth handling each of these
     * as a separate case. Technicaly this could leak memory on failure,
     * but a) it won't happen in practice, and b) it doesn't matter as we
     * will immediately exit with a failure code.
     */
    if (!tmp || !big2 || !big32 || !big2_32) {
        fprintf(stderr, "Out of memory (bignum)\n");
        return -ENOMEM;
    }
    ctx = BN_CTX_new();
    if (!tmp) {
        fprintf(stderr, "Out of memory (bignum context)\n");
        return -ENOMEM;
    }
    BN_set_word(big2, 2L);
    BN_set_word(big32, 32L);
    BN_exp(big2_32, big2, big32, ctx); /* B = 2^32 */

    size = nwords * sizeof(uint32_t);
    buf = malloc(size);
    if (!buf) {
        fprintf(stderr, "Out of memory (%d bytes)\n", size);
        return -ENOMEM;
    }

    /* Write out modulus as big endian array of integers */
    for (ptr = buf + nwords - 1; ptr >= buf; ptr--) {
        BN_mod(tmp, num, big2_32, ctx); /* n = N mod B */
        *ptr = cpu_to_fdt32(BN_get_word(tmp));
        BN_rshift(num, num, 32); /*  N = N/B */
    }

    /*
     * We try signing with successively increasing size values, so this
     * might fail several times
     */
    ret = fdt_setprop(blob, noffset, prop_name, buf, size);

    free(buf);
    BN_free(tmp);
    BN_free(big2);
    BN_free(big32);
    BN_free(big2_32);

    return ret ? -FDT_ERR_NOSPACE : 0;
}

static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey)
{
    EC_KEY *dtmp;
    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_EC_KEY(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (eckey) {
        EC_KEY_free(*eckey);
        *eckey = dtmp;
    }
    return dtmp;
}

/**
 * ec_pem_get_priv_key() - read a private key from a .key file
 *
 * @keydir:	Directory containing the key
 * @name	Name of key file (will have a .key extension)
 * @rsap	Returns EC object, or NULL on failure
 * @return 0 if ok, -ve on error (in which case *ecp will be set to NULL)
 */
static int ec_pem_get_priv_key(const char *keydir, const char *name,
				EC_KEY **ecp)
{
    char path[1024];
    EC_KEY *ec;
    FILE *f;
    EVP_PKEY *pktmp;

    *ecp = NULL;
    snprintf(path, sizeof(path), "%s/%s_priv.key", keydir, name);
    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Couldn't open EC private key: '%s': %s\n",
            path, strerror(errno));
        return -ENOENT;
    }

    pktmp = PEM_read_PrivateKey(f, 0, NULL, path);
    ec = pkey_get_eckey(pktmp, ecp);
    if (!ec) {
        fprintf(stderr, "Failure reading EC private key\n");
        fclose(f);
        return -EPROTO;
    }
    fclose(f);
    *ecp = ec;

    return 0;
}

/**
 * ec_pem_get_pub_key() - read a public key from a .key file
 *
 * @keydir:	Directory containing the key
 * @name	Name of key file (will have a .key extension)
 * @pub_key	Returns BIGNUM object, or NULL on failure
 * @return 0 if ok, -ve on error (in which case *pub_key will be set to NULL)
 */
static int ec_pem_get_pub_key(const char *keydir, const char *name, BIGNUM **pub_key)
{
    char path[1024];
    EC_KEY *ec;
    FILE *f;
    unsigned char *pub_k_cp = NULL;
    int ret;

    snprintf(path, sizeof(path), "%s/%s_public.key", keydir, name);
    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Couldn't open EC public key: '%s': %s\n",
            path, strerror(errno));
        return -ENOENT;
    }

    ec = PEM_read_EC_PUBKEY(f, 0, NULL, path);

    if (!ec) {
        fprintf(stderr, "Failure reading EC public key\n");
        fclose(f);
        return -EPROTO;
    }
    fclose(f);

    /* Transform from EC_POINT to char */
    ret = i2o_ECPublicKey(ec, &pub_k_cp);
    if (ret == 0) {
        return -1;
    } else {
       /* Transform from char to BIGNUM */
       *pub_key = BN_bin2bn(pub_k_cp, ret , NULL);
    }

    return 0;
}

int ecc_add_verify_data(struct image_sign_info *info, void *keydest)
{
    BIGNUM *pub_key;
    int parent, node;
    char name[100];
    int ret=0;
    int bits;

    // get public key
    if (info->tkc_tier_flag) {
        ret = ec_pem_get_pub_key(info->keydir, "oem", &pub_key);
    } else {
        ret = ec_pem_get_pub_key(info->keydir, info->keyname, &pub_key);
    }

    if (ret)
        goto err_get_pub_key;

    parent = fdt_subnode_offset(keydest, 0, FIT_SIG_NODENAME);
    if (parent == -FDT_ERR_NOTFOUND) {
        parent = fdt_add_subnode(keydest, 0, FIT_SIG_NODENAME);
        if (parent < 0) {
            ret = parent;
            if (ret != -FDT_ERR_NOSPACE) {
                fprintf(stderr, "Couldn't create signature node: %s\n",
                fdt_strerror(parent));
            }
        }
    }
    if (ret)
        goto done;

    /* Either create or overwrite the named key node */
    snprintf(name, sizeof(name), "key-%s", info->keyname);
    node = fdt_subnode_offset(keydest, parent, name);
    if (node == -FDT_ERR_NOTFOUND) {
        node = fdt_add_subnode(keydest, parent, name);
        if (node < 0) {
            ret = node;
            if (ret != -FDT_ERR_NOSPACE) {
                fprintf(stderr, "Could not create key subnode: %s\n",
                fdt_strerror(node));
            }
        }
    } else if (node < 0) {
        fprintf(stderr, "Cannot select keys parent: %s\n",
        fdt_strerror(node));
        ret = node;
    }

    if (!ret) {
        ret = fdt_setprop_string(keydest, node, "key-name-hint", info->keyname);
    }

    if (!ret) {
        bits = info->crypto->key_len * 16;
        ret = fdt_add_bignum(keydest, node, "ecc,public-key", pub_key, bits);
    }
    if (!ret) {
        ret = fdt_setprop_string(keydest, node, FIT_ALGO_PROP, info->name);
    }
    if (!ret && info->require_keys) {
        ret = fdt_setprop_string(keydest, node, "required", info->require_keys);
    }
done:
    BN_free(pub_key);
    if (ret) {
        ret = ret == -FDT_ERR_NOSPACE ? -ENOSPC : -EIO;
    }

err_get_pub_key:

    return ret;
}

static int ec_init(void)
{
    int ret;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ret = SSL_library_init();
#else
    ret = OPENSSL_init_ssl(0, NULL);
#endif
    if (!ret) {
        fprintf(stderr, "Failure to init SSL library\n");
        return -1;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_load_error_strings();

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_ciphers();
#endif

    return 0;
}

static void ec_remove(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
#ifdef HAVE_ERR_REMOVE_THREAD_STATE
    ERR_remove_thread_state(NULL);
#else
    ERR_remove_state(0);
#endif
    EVP_cleanup();
#endif
}

static int ec_sign_with_key(EC_KEY *ec, struct checksum_algo *checksum_algo,
		const struct image_region region[], int region_count,
		uint8_t **sigp, uint *sig_size)
{
    EVP_PKEY *key;
    EVP_PKEY_CTX *keyctx;
    EVP_MD_CTX *context;
    int size, ret = 0;
    uint8_t *sig;
    int i;

    key = EVP_PKEY_new();
    if (!key) {
        fprintf(stderr, "EVP_PKEY object creation failed \n");
        return -1;
    }

    if (!EVP_PKEY_set1_EC_KEY(key, ec)) {
        fprintf(stderr, "EVP key setup failed \n");
        ret = -1;
        goto err_set;
    }

    keyctx = EVP_PKEY_CTX_new(key, NULL);
    if (!keyctx) {
        fprintf(stderr, "EVP_PKEY_CTX object creation failed \n");
        ret = -1;
        goto err_set;
    }

    size = EVP_PKEY_size(key);
    sig = malloc(size);
    if (!sig) {
        fprintf(stderr, "Out of memory for signature (%d bytes)\n", size);
        ret = -ENOMEM;
        goto err_alloc;
    }

    context = EVP_MD_CTX_create();
    if (!context) {
        fprintf(stderr, "EVP context creation failed \n");
        ret = -1;
        goto err_create;
    }
    EVP_MD_CTX_init(context);
    if (!EVP_DigestSignInit(context, &keyctx, checksum_algo->calculate_sign(), NULL, key)) {
        fprintf(stderr, "Signer setup failed \n");
        ret = -1;
        goto err_sign;
    }

    for (i = 0; i < region_count; i++) {
        if (!EVP_DigestSignUpdate(context, region[i].data, region[i].size)) {
            fprintf(stderr, "Signing data failed \n");
            ret = -1;
            goto err_sign;
        }
    }

    if (!EVP_DigestSignFinal(context, sig, (size_t *)sig_size)) {
        fprintf(stderr, "Could not obtain signature \n");
        ret = -1;
        goto err_sign;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX_cleanup(context);
#else
    EVP_MD_CTX_reset(context);
#endif
    EVP_MD_CTX_destroy(context);
    EVP_PKEY_free(key);

    fprintf(stderr, "Got signature: %d bytes, expected %d\n", *sig_size, size);
    *sigp = sig;
    *sig_size = size;

    return 0;

err_sign:
    EVP_MD_CTX_destroy(context);
err_create:
    free(sig);
err_alloc:
err_set:
    EVP_PKEY_free(key);
    return ret;
}

int ecc_sign(struct image_sign_info *info,
	     const struct image_region region[], int region_count,
	     uint8_t **sigp, uint *sig_len)
{
    EC_KEY *ec;
    int ret = 0;

    ret = ec_init();
    if (ret)
        return ret;

    /* To read private key from pem */
    ret = ec_pem_get_priv_key(info->keydir, info->keyname, &ec);

    if (ret) {
        fprintf(stderr, "Failure reading EC private key\n");
        goto err_priv;
    }

    /* To signature */
    ret = ec_sign_with_key(ec, info->checksum, region,
        region_count, sigp, sig_len);
    if (ret) {
        goto err_sign;
    }


err_sign:

err_priv:
    ec_remove();

    return ret;
}

int ecc_add_tkc_data(struct image_sign_info *info, void *keydest)
{
    BIGNUM *pub_key;
    int tkc_parent, sign_node, key_node;
    int ret=0;
    int bits;

    // get public key
    ret = ec_pem_get_pub_key(info->keydir, "tier", &pub_key);
    if (ret)
        goto err_get_pub_key;

    // Step 1: detect trusted-key-certificate node
    // if not found, then create it
    tkc_parent = fdt_subnode_offset(keydest, 0, FIT_TKC_NODENAME);
    if (tkc_parent == -FDT_ERR_NOTFOUND) {
        tkc_parent = fdt_add_subnode(keydest, 0, FIT_TKC_NODENAME);
        if (tkc_parent < 0) {
            ret = tkc_parent;
            if (ret != -FDT_ERR_NOSPACE) {
                fprintf(stderr, "Couldn't create trusted-key-certificate node: %s\n",
                fdt_strerror(tkc_parent));
            }
        }
    }
    if (ret)
        goto done;

    // Step 2: detect sign-node node
    // if not found, then create it
    sign_node = fdt_subnode_offset(keydest, tkc_parent, FIT_TKC_SIGN_NODENAME);
    if (sign_node == -FDT_ERR_NOTFOUND) {
        sign_node = fdt_add_subnode(keydest, tkc_parent, FIT_TKC_SIGN_NODENAME);
        if (sign_node < 0) {
            ret = sign_node;
            if (ret != -FDT_ERR_NOSPACE) {
                fprintf(stderr, "Could not create sign-node subnode: %s\n",
                fdt_strerror(sign_node));
            }
        }
    }
    if (ret)
        goto done;

    // Step 3: detect trusted-key node
    // if not found, then create it
    key_node = fdt_subnode_offset(keydest, sign_node, FIT_TKC_KEY_NODENAME);
    if (key_node == -FDT_ERR_NOTFOUND) {
        key_node = fdt_add_subnode(keydest, sign_node, FIT_TKC_KEY_NODENAME);
        if (key_node < 0) {
            ret = key_node;
            if (ret != -FDT_ERR_NOSPACE) {
                fprintf(stderr, "Could not create trusted-key subnode: %s\n",
                fdt_strerror(key_node));
            }
        }
    }
    if (ret)
        goto done;

    // start to write key info into key_node
    if (!ret) {
        bits = info->crypto->key_len * 16;
        ret = fdt_add_bignum(keydest, key_node, "ecc,public-key", pub_key, bits);
    }

    if (!ret) {
        if (info->name) {
            ret = fdt_setprop_string(keydest, key_node, FIT_ALGO_PROP, info->name);
        }
    }

done:
    BN_free(pub_key);
    if (ret) {
        ret = ret == -FDT_ERR_NOSPACE ? -ENOSPC : -EIO;
    }

err_get_pub_key:

    return ret;
}
