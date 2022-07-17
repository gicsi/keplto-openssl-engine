/*
 * klepto.c versión 1.5
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


#include "klepto.h"


///////////////////////////////////////////////////////////////////////////////

// incialización de engine openssl
IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(klepto_bind);

// "instancia" de EVP_CIPHER
static EVP_CIPHER *cipher_aes_128_cbc_klepto = NULL;
static const EVP_CIPHER *get_cipher_aes_128_cbc_klepto(void)
{
    if (cipher_aes_128_cbc_klepto == NULL) {
        EVP_CIPHER *cipher;

        if ((cipher = EVP_CIPHER_meth_new(NID_aes_128_cbc, 16, 16)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(cipher, 16)
            || !EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_CBC_MODE | EVP_CIPH_ALWAYS_CALL_INIT)
            || !EVP_CIPHER_meth_set_init(cipher, cipher_aes_128_cbc_klepto_init)
            || !EVP_CIPHER_meth_set_do_cipher(cipher, cipher_aes_128_cbc_klepto_cipher)
            || !EVP_CIPHER_meth_set_cleanup(cipher, cipher_aes_128_cbc_klepto_clean)            
            || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(KLEPTO_CTX))
            || !EVP_CIPHER_meth_set_ctrl(cipher, cipher_aes_128_cbc_klepto_ctrl)
        )   {
            EVP_CIPHER_meth_free(cipher);
            cipher = NULL;
        }
        cipher_aes_128_cbc_klepto = cipher;
    }
    return cipher_aes_128_cbc_klepto;
}

// función para cargar el engine
static int klepto_bind(ENGINE *e, const char *id)   {
    dbg_printf("se cargará engine.\n");

    if (id && (strcmp(id, engine_klepto_id) != 0))  {
        return 0;
    }

    if (!ENGINE_set_id(e, engine_klepto_id)
        || !ENGINE_set_name(e, engine_klepto_name)
        || !ENGINE_set_destroy_function(e, klepto_destroy)
        || !ENGINE_set_init_function(e, klepto_init)
        || !ENGINE_set_ciphers(e, klepto_ciphers)
        || !ENGINE_register_ciphers(e)
    )   {
        err_printf("error al cargar engine openssl.\n");
        return 0;
    }
    return 1;
}

// función para inicializar engine
static int klepto_init(ENGINE *e) {
    dbg_printf("se inicializará engine.\n");

    return 1;
}

// función para informar a openssl de cipher implementado en engine
static int klepto_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)  {
    dbg_printf("se consultarán ciphers de engine.\n");

    if (!cipher)    {
        *nids = klepto_cipher_nids;
        return 1;   // un único cipher en este caso
    }
    if(nid == NID_aes_128_cbc)  {
        *cipher = get_cipher_aes_128_cbc_klepto();
    } else  {
        *cipher = NULL;
        return 0;
    }
    return 1;
}

///////////////////////////////////////////////////////////////////////////////

// incialización de cipher
static int cipher_aes_128_cbc_klepto_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)  {
    dbg_printf("se inicializará cipher.\n");

    // estructura ctx
    KLEPTO_CTX *klepto_ctx = (KLEPTO_CTX *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    int in_init = 0;

    // primera incialización?
    if (key == NULL && iv == NULL)  {
        dbg_printf("key == iv == NULL, inicialización de ctx.\n");
        // incializar datos (klepto_ctx)
        memset(klepto_ctx, 0, sizeof(KLEPTO_CTX));
        klepto_ctx->status |= KLEPTO_CIPHER_STATUS_CTX;
        in_init = 1;
    } else if (key != NULL && iv != NULL && (enc == 0 || enc == 1))   {
        // s_client inicializa enviando los tres parámetros de una vez
        dbg_printf("key != iv != NULL, enc == [01], inicialización de ctx.\n");
        memset(klepto_ctx, 0, sizeof(KLEPTO_CTX));
        klepto_ctx->status |= KLEPTO_CIPHER_STATUS_CTX;
        in_init = 1;
    }

    // cifrar (1) o decifrar (0)? (openvpn usa -1 cuando actualiza iv)
    if (enc == 0 || enc == 1)   {
        dbg_printf("enc = %d\n", enc);
        klepto_ctx->enc = enc;
        klepto_ctx->status |= KLEPTO_CIPHER_STATUS_ENC;
    }

    // inicializa llave?
    if (key != NULL)    {
        dbg_buf2hexstr_128("key = ", key);
        memcpy(klepto_ctx->key, key, sizeof(klepto_ctx->key));
        // setup de openssl para llave aes
        if (klepto_ctx->enc == 1)   {   // cifrar
            if (AES_set_encrypt_key(klepto_ctx->key, sizeof(klepto_ctx->key) * 8, &(klepto_ctx->key_aes_openssl)) != 0) {
                err_printf("error al utilizar cipher (aes en openssl).\n");
                return 0;
            }
        } else  {   // decifrar
            if (AES_set_decrypt_key(klepto_ctx->key, sizeof(klepto_ctx->key) * 8, &(klepto_ctx->key_aes_openssl)) != 0) {
                err_printf("error al utilizar cipher (aes en openssl).\n");
                return 0;
            }
        }
        // actualizar status
        klepto_ctx->status |= KLEPTO_CIPHER_STATUS_KEY;
    }

    // inicializa iv?
    if (iv != NULL) {
        dbg_buf2hexstr_128("iv = ", iv);

        memcpy(klepto_ctx->iv, iv, sizeof(klepto_ctx->iv));
        // actualizar status
        klepto_ctx->status |= KLEPTO_CIPHER_STATUS_IV;
    }

    klepto_ctx->klepto_iv_sent = 0;

    return 1;
}

// función que implementa el cifrado y decifrado del cipher
static int cipher_aes_128_cbc_klepto_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)   {
    dbg_printf("se cifrará/decifrará vía cipher.\n");
    
    // estructura ctx
    KLEPTO_CTX *klepto_ctx = (KLEPTO_CTX *) EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (klepto_ctx->status != KLEPTO_CIPHER_STATUS_OK)  {
        err_printf("estado de cipher incorrecto (%d).\n", klepto_ctx->status);
        return 0;
    }

    // debug general, eliminado al no compilar con -DDEBUG
    dbg_buf2hexstr_128("klepto_ctx->iv = ", klepto_ctx->iv);
    dbg_buf2hexstr_128("klepto_ctx->key = ", klepto_ctx->key);
    dbg_buf2hexstr_XXX("pre - entrada", in, inl);
    
    // cifrado
    if (klepto_ctx->enc == 1)   {
        dbg_printf("se invoca para cifrado de %d bytes.\n", inl);
        // sustitución de IV - openssl - TLS 1.1/1.2
        // primer bloque cifrado es utilizado como IV explícito; RFC TLS 1.1 - 6.2.3.2 - (2)(b)
        // chequeo type 20, length 12
        if (! klepto_ctx->klepto_iv_sent && inl >= (16 + 4) && in[16+0] == 0x14 && in[16+1] == 0x00 && in[16+2] == 0x00 && in[16+3] == 0x0c)   {
            for (int i=0; i<16; i++)    {
                out[i] = klepto_ctx->key[i] ^ KLEPTO_XOR_KEY[i];
                klepto_ctx->iv[i] = out[i];
            }
            AES_cbc_encrypt(in+16, out+16, inl-16, &(klepto_ctx->key_aes_openssl), klepto_ctx->iv, AES_ENCRYPT);
            klepto_ctx->klepto_iv_sent = 1;
        } else
            AES_cbc_encrypt(in, out, inl, &(klepto_ctx->key_aes_openssl), klepto_ctx->iv, AES_ENCRYPT);
    // decifrado
    } else  {
        dbg_printf("se invoca para decifrado de %d bytes.\n", inl);
        AES_cbc_encrypt(in, out, inl, &(klepto_ctx->key_aes_openssl), klepto_ctx->iv, AES_DECRYPT);
    }

    dbg_buf2hexstr_XXX("post - salida", out, inl);

    return 1;
}

// función que implementa la limpieza del cipher
static int cipher_aes_128_cbc_klepto_clean(EVP_CIPHER_CTX *ctx) {
    dbg_printf("se invoca limpieza de cipher.\n");

    return 1;
}

// función que implementa el proceso de comandos de control
static int cipher_aes_128_cbc_klepto_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)    {
    dbg_printf("se invoca ctrl de cipher.\n");

    return 1;
}

// función que implementa la limpieza del engine
int klepto_destroy(ENGINE *e)   {
    dbg_printf("se invoca limpieza de engine.\n");

    EVP_CIPHER_meth_free(cipher_aes_128_cbc_klepto);
    cipher_aes_128_cbc_klepto = NULL;

    return 1;
}

