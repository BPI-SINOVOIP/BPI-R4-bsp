#include <mtk_crypto.h>
#include <hacc_export.h>
#include <string.h>

typedef enum {
    SEJ_ENCRYPT,
    SEJ_DECRYPT
} SEJ_OPERATION;

static uint32_t sej_operation(uint8_t *in, uint8_t *out,
			      unsigned int len, SEJ_OPERATION oper)
{
	if (!in || !out || !len)
		return 1;

	memcpy(out, in, len);

	if (oper == SEJ_ENCRYPT)
		sp_hacc_enc(out, len, HACC_USER1);
	else if (oper == SEJ_DECRYPT)
		sp_hacc_dec(out, len, HACC_USER1);
	else
		return 1;

	return 0;
}

uint32_t sej_encrypt(uint8_t *in, uint8_t *out, unsigned int len)
{
	return sej_operation(in, out, len, SEJ_ENCRYPT);
}

uint32_t sej_decrypt(uint8_t *in, uint8_t *out, unsigned int len)
{
	return sej_operation(in, out, len, SEJ_DECRYPT);
}
