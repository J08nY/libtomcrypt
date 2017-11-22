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
  @file der_decode_custom_type.c
  ASN.1 DER, decode a Custom type, Steffen Jaeckel
*/

#ifdef LTC_DER

/**
   Decode a Custom type
   @param in       The DER encoded input
   @param inlen    The size of the input
   @param root     The item that defines the custom type to decode
   @return CRYPT_OK on success
*/
int der_decode_custom_type(const unsigned char *in, unsigned long  inlen,
                           ltc_asn1_list *root)
{
   int           err, i;
   ltc_asn1_type type;
   ltc_asn1_list ident, *list;
   unsigned long size, x, y, z, blksize, outlen;
   void          *data;

   LTC_ARGCHK(in   != NULL);
   LTC_ARGCHK(root != NULL);

   if (root->type != LTC_ASN1_CUSTOM_TYPE) {
      return CRYPT_INVALID_PACKET;
   }
   /* We currently can't decode primitive Custom-types. */
   if (root->pc == LTC_ASN1_PC_PRIMITIVE) {
      return CRYPT_INVALID_PACKET;
   }
   /* get blk size */
   if (inlen < 2) {
      return CRYPT_INVALID_PACKET;
   }

   x = 0;
   y = inlen;
   if ((err = der_decode_asn1_identifier(in, &y, &ident)) != CRYPT_OK) {
      return err;
   }
   if ((ident.type != root->type) ||
         (ident.class != root->class) ||
         (ident.pc != root->pc) ||
         (ident.tag != root->tag)) {
      return CRYPT_INVALID_PACKET;
   }
   x += y;

   y = inlen - x;
   if ((err = der_decode_asn1_length(&in[x], &y, &blksize)) != CRYPT_OK) {
      return err;
   }
   x += y;

   /* would this blksize overflow? */
   if (x + blksize > inlen) {
      return CRYPT_INVALID_PACKET;
   }

   list = root->data;
   outlen = root->size;

   /* mark all as unused */
   for (i = 0; i < (int)outlen; i++) {
       list[i].used = 0;
   }

   /* ok read data */
   inlen = blksize;
   for (i = 0; i < (int)outlen; i++) {
       z    = 0;
       type = list[i].type;
       size = list[i].size;
       data = list[i].data;

       if (type == LTC_ASN1_EOL) {
          break;
       }

       switch (type) {
           case LTC_ASN1_BOOLEAN:
               z = inlen;
               if ((err = der_decode_boolean(in + x, z, ((int *)data))) != CRYPT_OK) {
                   goto LBL_ERR;
               }
               if ((err = der_length_boolean(&z)) != CRYPT_OK) {
                   goto LBL_ERR;
               }
               break;

           case LTC_ASN1_INTEGER:
               z = inlen;
               if ((err = der_decode_integer(in + x, z, data)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               if ((err = der_length_integer(data, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SHORT_INTEGER:
               z = inlen;
               if ((err = der_decode_short_integer(in + x, z, data)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               if ((err = der_length_short_integer(((unsigned long*)data)[0], &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }

               break;

           case LTC_ASN1_BIT_STRING:
               z = inlen;
               if ((err = der_decode_bit_string(in + x, z, data, &size)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_bit_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_RAW_BIT_STRING:
               z = inlen;
               if ((err = der_decode_raw_bit_string(in + x, z, data, &size)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_bit_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_OCTET_STRING:
               z = inlen;
               if ((err = der_decode_octet_string(in + x, z, data, &size)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_octet_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_NULL:
               if (inlen < 2 || in[x] != 0x05 || in[x+1] != 0x00) {
                  err = CRYPT_INVALID_PACKET;
                  goto LBL_ERR;
               }
               z = 2;
               break;

           case LTC_ASN1_OBJECT_IDENTIFIER:
               z = inlen;
               if ((err = der_decode_object_identifier(in + x, z, data, &size)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_object_identifier(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_TELETEX_STRING:
               z = inlen;
               if ((err = der_decode_teletex_string(in + x, z, data, &size)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_teletex_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_IA5_STRING:
               z = inlen;
               if ((err = der_decode_ia5_string(in + x, z, data, &size)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_ia5_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_PRINTABLE_STRING:
               z = inlen;
               if ((err = der_decode_printable_string(in + x, z, data, &size)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_printable_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_UTF8_STRING:
               z = inlen;
               if ((err = der_decode_utf8_string(in + x, z, data, &size)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_utf8_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_UTCTIME:
               z = inlen;
               if ((err = der_decode_utctime(in + x, &z, data)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_GENERALIZEDTIME:
               z = inlen;
               if ((err = der_decode_generalizedtime(in + x, &z, data)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SET:
               z = inlen;
               if ((err = der_decode_set(in + x, z, data, size)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               if ((err = der_length_sequence(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SETOF:
           case LTC_ASN1_SEQUENCE:
               /* detect if we have the right type */
               if ((type == LTC_ASN1_SETOF && (in[x] & 0x3F) != 0x31) || (type == LTC_ASN1_SEQUENCE && (in[x] & 0x3F) != 0x30)) {
                  err = CRYPT_INVALID_PACKET;
                  goto LBL_ERR;
               }

               z = inlen;
               if ((err = der_decode_sequence(in + x, z, data, size)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               if ((err = der_length_sequence(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_CUSTOM_TYPE:
               z = inlen;
               if ((err = der_decode_custom_type(in + x, z, data)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               if ((err = der_length_custom_type(data, &z, NULL)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_CHOICE:
               z = inlen;
               if ((err = der_decode_choice(in + x, &z, data, size)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_CONSTRUCTED:
           case LTC_ASN1_CONTEXT_SPECIFIC:
           case LTC_ASN1_EOL:
               err = CRYPT_INVALID_ARG;
               goto LBL_ERR;
       }
       x           += z;
       inlen       -= z;
       list[i].used = 1;
   }

   for (i = 0; i < (int)outlen; i++) {
      if (list[i].used == 0 && list[i].optional == 0) {
          err = CRYPT_INVALID_PACKET;
          goto LBL_ERR;
      }
   }

   if (inlen == 0) {
      err = CRYPT_OK;
   } else {
      err = CRYPT_INPUT_TOO_LONG;
   }

LBL_ERR:
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
