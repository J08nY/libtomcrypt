/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt.h"

/**
  @file der_decode_asn1_length.c
  ASN.1 DER, decode the ASN.1 Length field, Steffen Jaeckel
*/

#ifdef LTC_DER
/**
  Decode the ASN.1 Length field
  @param in       Where to read the length field from
  @param inlen    [in/out] The size of in available/read
  @param outlen   [out] The decoded ASN.1 length
  @return CRYPT_OK if successful
*/
int der_decode_asn1_length(const unsigned char *in, unsigned long *inlen, unsigned long *outlen)
{
   unsigned long real_len, offset;

   LTC_ARGCHK(in    != NULL);
   LTC_ARGCHK(inlen != NULL);

   if (*inlen < 1) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   offset = 0;
   real_len = in[offset++];

   if (real_len < 128) {
      if (outlen != NULL) {
         *outlen = real_len;
      }
   } else {
      real_len &= 0x7F;
      if (real_len == 0) {
         return CRYPT_PK_ASN1_ERROR;
      } else if (real_len > sizeof(*outlen)) {
         return CRYPT_OVERFLOW;
      } else if (real_len > (*inlen - 2)) {
         return CRYPT_BUFFER_OVERFLOW;
      }
      if (outlen != NULL) {
         *outlen = 0;
         while (real_len--) {
            *outlen = (*outlen<<8) | in[offset++];
         }
      } else {
         offset += real_len;
      }
   }
   *inlen = offset;

   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
