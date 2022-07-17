/*
 * klepto.h versión 1.1
 * 
 * Copyright 2020 GICSI. All Rights Reserved.
 *
 * Implementación de engine openssl KLEPTO.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR NOR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, NOR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/ossl_typ.h>


// id y descripción de engine para openssl
static const char *engine_klepto_id = "klepto";
static const char *engine_klepto_name = "KLEPTO engine - GICSI";

// algoritmos/modos que implementa este engine, de acuerdo a NIDs openssl
static int klepto_cipher_nids[] = { NID_aes_128_cbc, 0 };

// para cargar, inicializar y establecer parámetros del engine y cipher
static int klepto_bind(ENGINE * e, const char *id);
static int klepto_init(ENGINE *e);
static int klepto_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);
static int klepto_destroy(ENGINE *e);

// funciones que implementa el engine (inicialización, cifrado, limpieza, parametrización, ...)
static int cipher_aes_128_cbc_klepto_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
static int cipher_aes_128_cbc_klepto_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
static int cipher_aes_128_cbc_klepto_clean(EVP_CIPHER_CTX *ctx);
static int cipher_aes_128_cbc_klepto_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

// estructura cxt (estado, contexto) para cipher del engine
struct cipher_aes_128_cbc_klepto_ctx {
#define KLEPTO_CIPHER_STATUS_CTX 0x01
#define KLEPTO_CIPHER_STATUS_ENC 0x02
#define KLEPTO_CIPHER_STATUS_KEY 0x04
#define KLEPTO_CIPHER_STATUS_IV 0x08
#define KLEPTO_CIPHER_STATUS_OK 0x0F
 	int status;
	int enc;
	unsigned char key[16];
	unsigned char iv[16];
	AES_KEY key_aes_openssl;
    int klepto_iv_sent;
};
typedef struct cipher_aes_128_cbc_klepto_ctx KLEPTO_CTX;


// macros generales para impresión de mensajes de error y debug, a strerr y stdout respectivamente
#define err_printf(fmt, ...) do { if (ERRORMSGS) fprintf(stderr, "KLEPTO engine ERROR: %s:%d:%s(): " \
 fmt, __FILE__, __LINE__, __func__, ## __VA_ARGS__); } while (0)
#define dbg_printf(fmt, ...) do { if (DEBUGMSGS) fprintf(stdout, "KLEPTO engine DEBUG: %s:%d:%s(): " \
 fmt, __FILE__, __LINE__, __func__, ## __VA_ARGS__); } while (0)

#define dbg_buf2hexstr_128(lbl, buf) dbg_printf( \
 "%s%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", \
 lbl, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], \
 buf[12], buf[13], buf[14], buf[15]);

#define dbg_buf2hexstr_XXX(lbl, buf, len) dbg_printf("%s: %d bytes.\n", lbl, len); for (int i=0; i<len/16; i++) { \
 char lbl_buf[32]; \
 sprintf(lbl_buf, " %d: ", i); \
 dbg_buf2hexstr_128(lbl_buf, (unsigned char *)(buf + (i * 16))); }


// llave "kleptográfica" para generar IV explícito (IV = KLEPTO_XOR_KEY xor llave aes_128_cbc)
const unsigned char KLEPTO_XOR_KEY[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

