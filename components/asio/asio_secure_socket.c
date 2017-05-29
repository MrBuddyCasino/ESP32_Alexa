/*
 * asio_handler_ssl.c
 *
 *  Created on: 23.05.2017
 *      Author: michaelboeckling
 */


/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include "esp_log.h"
#include "common_buffer.h"
#include "brssl.h"
#include "url_parser.h"
#include "asio.h"
#include "asio_socket.h"

#define TAG "asio_handler_ssl"
#define SOCKET           int
#define INVALID_SOCKET   (-1)

static void
dump_blob(const char *name, const void *data, size_t len)
{
    const unsigned char *buf;
    size_t u;

    buf = data;
    fprintf(stderr, "%s (len = %lu)", name, (unsigned long)len);
    for (u = 0; u < len; u ++) {
        if ((u & 15) == 0) {
            fprintf(stderr, "\n%08lX  ", (unsigned long)u);
        } else if ((u & 7) == 0) {
            fprintf(stderr, " ");
        }
        fprintf(stderr, " %02x", buf[u]);
    }
    fprintf(stderr, "\n");
}

/*
 * Inspect the provided data in case it is a "command" to trigger a
 * special behaviour. If the command is recognised, then it is executed
 * and this function returns 1. Otherwise, this function returns 0.
 */
static int
run_command(br_ssl_engine_context *cc, unsigned char *buf, size_t len)
{
    /*
     * A single static slot for saving session parameters.
     */
    static br_ssl_session_parameters slot;
    static int slot_used = 0;

    size_t u;

    if (len < 2 || len > 3) {
        return 0;
    }
    if (len == 3 && (buf[1] != '\r' || buf[2] != '\n')) {
        return 0;
    }
    if (len == 2 && buf[1] != '\n') {
        return 0;
    }
    switch (buf[0]) {
    case 'Q':
        fprintf(stderr, "closing...\n");
        br_ssl_engine_close(cc);
        return 1;
    case 'R':
        if (br_ssl_engine_renegotiate(cc)) {
            fprintf(stderr, "renegotiating...\n");
        } else {
            fprintf(stderr, "not renegotiating.\n");
        }
        return 1;
    case 'F':
        /*
         * Session forget is nominally client-only. But the
         * session parameters are in the engine structure, which
         * is the first field of the client context, so the cast
         * still works properly. On the server, this forgetting
         * has no effect.
         */
        fprintf(stderr, "forgetting session...\n");
        br_ssl_client_forget_session((br_ssl_client_context *)cc);
        return 1;
    case 'S':
        fprintf(stderr, "saving session parameters...\n");
        br_ssl_engine_get_session_parameters(cc, &slot);
        fprintf(stderr, "  id = ");
        for (u = 0; u < slot.session_id_len; u ++) {
            fprintf(stderr, "%02X", slot.session_id[u]);
        }
        fprintf(stderr, "\n");
        slot_used = 1;
        return 1;
    case 'P':
        if (slot_used) {
            fprintf(stderr, "restoring session parameters...\n");
            fprintf(stderr, "  id = ");
            for (u = 0; u < slot.session_id_len; u ++) {
                fprintf(stderr, "%02X", slot.session_id[u]);
            }
            fprintf(stderr, "\n");
            br_ssl_engine_set_session_parameters(cc, &slot);
            return 1;
        }
        return 0;
    default:
        return 0;
    }
}

void print_algos(br_ssl_engine_context* cc)
{
    fprintf(stderr, "Algorithms:\n");
    if (cc->iaes_cbcenc != 0) {
        fprintf(stderr, "   AES/CBC (enc): %s\n",
                get_algo_name(cc->iaes_cbcenc, 0));
    }
    if (cc->iaes_cbcdec != 0) {
        fprintf(stderr, "   AES/CBC (dec): %s\n",
                get_algo_name(cc->iaes_cbcdec, 0));
    }
    if (cc->iaes_ctr != 0) {
        fprintf(stderr, "   AES/CTR:       %s\n",
                get_algo_name(cc->iaes_cbcdec, 0));
    }
    if (cc->ides_cbcenc != 0) {
        fprintf(stderr, "   DES/CBC (enc): %s\n",
                get_algo_name(cc->ides_cbcenc, 0));
    }
    if (cc->ides_cbcdec != 0) {
        fprintf(stderr, "   DES/CBC (dec): %s\n",
                get_algo_name(cc->ides_cbcdec, 0));
    }
    if (cc->ighash != 0) {
        fprintf(stderr, "   GHASH (GCM):   %s\n", get_algo_name(cc->ighash, 0));
    }
    if (cc->ichacha != 0) {
        fprintf(stderr, "   ChaCha20:      %s\n",
                get_algo_name(cc->ichacha, 0));
    }
    if (cc->ipoly != 0) {
        fprintf(stderr, "   Poly1305:      %s\n", get_algo_name(cc->ipoly, 0));
    }
    if (cc->iec != 0) {
        fprintf(stderr, "   EC:            %s\n", get_algo_name(cc->iec, 0));
    }
    if (cc->iecdsa != 0) {
        fprintf(stderr, "   ECDSA:         %s\n", get_algo_name(cc->iecdsa, 0));
    }
    if (cc->irsavrfy != 0) {
        fprintf(stderr, "   RSA (vrfy):    %s\n",
                get_algo_name(cc->irsavrfy, 0));
    }
}

int handle_closed(int verbose, br_ssl_engine_context* cc)
{
    int err;
    int retcode;
    err = br_ssl_engine_last_error(cc);
    if (err == BR_ERR_OK) {
        if (verbose) {
            fprintf(stderr, "SSL closed normally\n");
        }
        retcode = 0;
    } else {
        fprintf(stderr, "ERROR: SSL error %d", err);
        retcode = err;
        if (err >= BR_ERR_SEND_FATAL_ALERT) {
            err -= BR_ERR_SEND_FATAL_ALERT;
            fprintf(stderr, " (sent alert %d)\n", err);
        } else if (err >= BR_ERR_RECV_FATAL_ALERT) {
            err -= BR_ERR_RECV_FATAL_ALERT;
            fprintf(stderr, " (received alert %d)\n", err);
        } else {
            const char* ename;
            ename = find_error_name(err, NULL);
            if (ename == NULL) {
                ename = "unknown";
            }
            fprintf(stderr, " (%s)\n", ename);
        }
    }
    return retcode;
}

void print_handshake_result(br_ssl_engine_context* cc)
{
    char csn[80];
    const char* pname;
    fprintf(stderr, "Handshake completed\n");
    fprintf(stderr, "   version:               ");
    switch (cc->session.version) {
        case BR_SSL30:
            fprintf(stderr, "SSL 3.0");
            break;
        case BR_TLS10:
            fprintf(stderr, "TLS 1.0");
            break;
        case BR_TLS11:
            fprintf(stderr, "TLS 1.1");
            break;
        case BR_TLS12:
            fprintf(stderr, "TLS 1.2");
            break;
        default:
            fprintf(stderr, "unknown (0x%04X)", (unsigned) cc->session.version);
            break;
    }
    fprintf(stderr, "\n");
    get_suite_name_ext(cc->session.cipher_suite, csn, sizeof csn);
    fprintf(stderr, "   cipher suite:          %s\n", csn);
    if (uses_ecdhe(cc->session.cipher_suite)) {
        get_curve_name_ext(br_ssl_engine_get_ecdhe_curve(cc), csn, sizeof csn);
        fprintf(stderr, "   ECDHE curve:           %s\n", csn);
    }
    fprintf(stderr, "   secure renegotiation:  %s\n",
            cc->reneg == 1 ? "no" : "yes");
    pname = br_ssl_engine_get_selected_protocol(cc);
    if (pname != NULL) {
        fprintf(stderr, "   protocol name (ALPN):  %s\n", pname);
    }
    //return csn;
}



typedef struct {
    const br_ssl_client_certificate_class *vtable;
    int verbose;
    br_x509_certificate *chain;
    size_t chain_len;
    private_key *sk;
    int issuer_key_type;
} ccert_context;

static void
cc_start_name_list(const br_ssl_client_certificate_class **pctx)
{
    ccert_context *zc;

    zc = (ccert_context *)pctx;
    if (zc->verbose) {
        fprintf(stderr, "Server requests a client certificate.\n");
        fprintf(stderr, "--- anchor DN list start ---\n");
    }
}

static void
cc_start_name(const br_ssl_client_certificate_class **pctx, size_t len)
{
    ccert_context *zc;

    zc = (ccert_context *)pctx;
    if (zc->verbose) {
        fprintf(stderr, "new anchor name, length = %u\n",
            (unsigned)len);
    }
}

static void
cc_append_name(const br_ssl_client_certificate_class **pctx,
    const unsigned char *data, size_t len)
{
    ccert_context *zc;

    zc = (ccert_context *)pctx;
    if (zc->verbose) {
        size_t u;

        for (u = 0; u < len; u ++) {
            if (u == 0) {
                fprintf(stderr, "  ");
            } else if (u > 0 && u % 16 == 0) {
                fprintf(stderr, "\n  ");
            }
            fprintf(stderr, " %02x", data[u]);
        }
        if (len > 0) {
            fprintf(stderr, "\n");
        }
    }
}

static void
cc_end_name(const br_ssl_client_certificate_class **pctx)
{
    (void)pctx;
}

static void
cc_end_name_list(const br_ssl_client_certificate_class **pctx)
{
    ccert_context *zc;

    zc = (ccert_context *)pctx;
    if (zc->verbose) {
        fprintf(stderr, "--- anchor DN list end ---\n");
    }
}

static void
print_hashes(unsigned hh, unsigned hh2)
{
    int i;

    for (i = 0; i < 8; i ++) {
        const char *name;

        name = hash_function_name(i);
        if (((hh >> i) & 1) != 0) {
            fprintf(stderr, " %s", name);
        } else if (((hh2 >> i) & 1) != 0) {
            fprintf(stderr, " (%s)", name);
        }
    }
}

static int
choose_hash(unsigned hh)
{
    static const int f[] = {
        br_sha256_ID, br_sha224_ID, br_sha384_ID, br_sha512_ID,
        br_sha1_ID, br_md5sha1_ID, -1
    };

    size_t u;

    for (u = 0; f[u] >= 0; u ++) {
        if (((hh >> f[u]) & 1) != 0) {
            return f[u];
        }
    }
    return -1;
}

static void
cc_choose(const br_ssl_client_certificate_class **pctx,
    const br_ssl_client_context *cc, uint32_t auth_types,
    br_ssl_client_certificate *choices)
{
    ccert_context *zc;
    int scurve;

    zc = (ccert_context *)pctx;
    scurve = br_ssl_client_get_server_curve(cc);
    if (zc->verbose) {
        unsigned hashes;

        hashes = br_ssl_client_get_server_hashes(cc);
        if ((auth_types & 0x00FF) != 0) {
            fprintf(stderr, "supported: RSA signatures:");
            print_hashes(auth_types, hashes);
            fprintf(stderr, "\n");
        }
        if ((auth_types & 0xFF00) != 0) {
            fprintf(stderr, "supported: ECDSA signatures:");
            print_hashes(auth_types >> 8, hashes >> 8);
            fprintf(stderr, "\n");
        }
        if ((auth_types & 0x010000) != 0) {
            fprintf(stderr, "supported:"
                " fixed ECDH (cert signed with RSA)\n");
        }
        if ((auth_types & 0x020000) != 0) {
            fprintf(stderr, "supported:"
                " fixed ECDH (cert signed with ECDSA)\n");
        }
        if (scurve) {
            fprintf(stderr, "server key curve: %s (%d)\n",
                ec_curve_name(scurve), scurve);
        } else {
            fprintf(stderr, "server key is not EC\n");
        }
    }
    switch (zc->sk->key_type) {
    case BR_KEYTYPE_RSA:
        if ((choices->hash_id = choose_hash(auth_types)) >= 0) {
            if (zc->verbose) {
                fprintf(stderr, "using RSA, hash = %d (%s)\n",
                    choices->hash_id,
                    hash_function_name(choices->hash_id));
            }
            choices->auth_type = BR_AUTH_RSA;
            choices->chain = zc->chain;
            choices->chain_len = zc->chain_len;
            return;
        }
        break;
    case BR_KEYTYPE_EC:
        if (zc->issuer_key_type != 0
            && scurve == zc->sk->key.ec.curve)
        {
            int x;

            x = (zc->issuer_key_type == BR_KEYTYPE_RSA) ? 16 : 17;
            if (((auth_types >> x) & 1) != 0) {
                if (zc->verbose) {
                    fprintf(stderr, "using static ECDH\n");
                }
                choices->auth_type = BR_AUTH_ECDH;
                choices->hash_id = -1;
                choices->chain = zc->chain;
                choices->chain_len = zc->chain_len;
                return;
            }
        }
        if ((choices->hash_id = choose_hash(auth_types >> 8)) >= 0) {
            if (zc->verbose) {
                fprintf(stderr, "using ECDSA, hash = %d (%s)\n",
                    choices->hash_id,
                    hash_function_name(choices->hash_id));
            }
            choices->auth_type = BR_AUTH_ECDSA;
            choices->chain = zc->chain;
            choices->chain_len = zc->chain_len;
            return;
        }
        break;
    }
    if (zc->verbose) {
        fprintf(stderr, "no matching client certificate\n");
    }
    choices->chain = NULL;
    choices->chain_len = 0;
}

static uint32_t
cc_do_keyx(const br_ssl_client_certificate_class **pctx,
    unsigned char *data, size_t *len)
{
    const br_ec_impl *iec;
    ccert_context *zc;
    size_t xoff, xlen;
    uint32_t r;

    zc = (ccert_context *)pctx;
    iec = br_ec_get_default();
    r = iec->mul(data, *len, zc->sk->key.ec.x,
        zc->sk->key.ec.xlen, zc->sk->key.ec.curve);
    xoff = iec->xoff(zc->sk->key.ec.curve, &xlen);
    memmove(data, data + xoff, xlen);
    *len = xlen;
    return r;
}

static size_t
cc_do_sign(const br_ssl_client_certificate_class **pctx,
    int hash_id, size_t hv_len, unsigned char *data, size_t len)
{
    ccert_context *zc;
    unsigned char hv[64];

    zc = (ccert_context *)pctx;
    memcpy(hv, data, hv_len);
    switch (zc->sk->key_type) {
        const br_hash_class *hc;
        const unsigned char *hash_oid;
        uint32_t x;
        size_t sig_len;

    case BR_KEYTYPE_RSA:
        hash_oid = get_hash_oid(hash_id);
        if (hash_oid == NULL && hash_id != 0) {
            if (zc->verbose) {
                fprintf(stderr, "ERROR: cannot RSA-sign with"
                    " unknown hash function: %d\n",
                    hash_id);
            }
            return 0;
        }
        sig_len = (zc->sk->key.rsa.n_bitlen + 7) >> 3;
        if (len < sig_len) {
            if (zc->verbose) {
                fprintf(stderr, "ERROR: cannot RSA-sign,"
                    " buffer is too small"
                    " (sig=%lu, buf=%lu)\n",
                    (unsigned long)sig_len,
                    (unsigned long)len);
            }
            return 0;
        }
        x = br_rsa_pkcs1_sign_get_default()(
            hash_oid, hv, hv_len, &zc->sk->key.rsa, data);
        if (!x) {
            if (zc->verbose) {
                fprintf(stderr, "ERROR: RSA-sign failure\n");
            }
            return 0;
        }
        return sig_len;

    case BR_KEYTYPE_EC:
        hc = get_hash_impl(hash_id);
        if (hc == NULL) {
            if (zc->verbose) {
                fprintf(stderr, "ERROR: cannot ECDSA-sign with"
                    " unknown hash function: %d\n",
                    hash_id);
            }
            return 0;
        }
        if (len < 139) {
            if (zc->verbose) {
                fprintf(stderr, "ERROR: cannot ECDSA-sign"
                    " (output buffer = %lu)\n",
                    (unsigned long)len);
            }
            return 0;
        }
        sig_len = br_ecdsa_sign_asn1_get_default()(
            br_ec_get_default(), hc, hv, &zc->sk->key.ec, data);
        if (sig_len == 0) {
            if (zc->verbose) {
                fprintf(stderr, "ERROR: ECDSA-sign failure\n");
            }
            return 0;
        }
        return sig_len;

    default:
        return 0;
    }
}

static const br_ssl_client_certificate_class ccert_vtable = {
    sizeof(ccert_context),
    cc_start_name_list,
    cc_start_name,
    cc_append_name,
    cc_end_name,
    cc_end_name_list,
    cc_choose,
    cc_do_keyx,
    cc_do_sign
};

static void
free_alpn(void *alpn)
{
    xfree(*(char **)alpn);
}



typedef struct {
    asio_event_handler_t delegate_io_handler;
    int hsdetails;
    int verbose;
    int trace;
    int bidi;
    br_ssl_client_context *cc;
    cipher_suite *suites;
    size_t num_suites;
    uint16_t *suite_ids;
    anchor_list *anchors;
    char *alpn;
    VECTOR(char *) alpn_names;
    br_x509_certificate *chain;
    size_t chain_len;
    private_key *sk;
    unsigned char *iobuf;
    ccert_context *zc;
    br_x509_minimal_context *xc;
    x509_noanchor_context *xwc;
    br_hash_class *dnhash;
} ssl_proto_ctx_t;


asio_cb_res_t asio_ssl_connect(asio_connection_t *conn, asio_event_t event)
{
    ssl_proto_ctx_t *proto_ctx = conn->io_ctx;

    if(proto_ctx->delegate_io_handler(conn, event) != ASIO_CB_OK) {
        return ASIO_CB_CLOSE_CONNECTION;
    }

    unsigned vmin, vmax;
    unsigned hfuns;
    size_t u;
    int nostaticecdh;
    size_t iobuf_len;
    size_t minhello_len;
    int fallback;
    uint32_t flags;

    vmin = 0;
    vmax = 0;
    hfuns = 0;
    nostaticecdh = 0;
    iobuf_len = 0;
    minhello_len = (size_t)-1;
    fallback = 0;
    flags = 0;

    if (proto_ctx->chain == NULL && proto_ctx->sk != NULL) {
        fprintf(stderr, "ERROR: private key specified, but"
            " no certificate chain\n");
        return ASIO_CB_ERR;
    }
    if (proto_ctx->chain != NULL && proto_ctx->sk == NULL) {
        fprintf(stderr, "ERROR: certificate chain specified, but"
            " no private key\n");
        return ASIO_CB_ERR;
    }

    if (vmin == 0) {
        vmin = BR_TLS10;
    }
    if (vmax == 0) {
        vmax = BR_TLS12;
    }
    if (vmax < vmin) {
        fprintf(stderr, "ERROR: impossible minimum/maximum protocol"
            " version combination\n");
        return ASIO_CB_ERR;
    }

    if (proto_ctx->suites == NULL) {
        proto_ctx->num_suites = 0;

        for (u = 0; cipher_suites[u].name; u ++) {
            if ((cipher_suites[u].req & REQ_TLS12) == 0
                || vmax >= BR_TLS12)
            {
                proto_ctx->num_suites++;
            }
        }
        proto_ctx->suites = xmalloc(proto_ctx->num_suites * sizeof *(proto_ctx->suites));
        proto_ctx->num_suites = 0;
        for (u = 0; cipher_suites[u].name; u ++) {
            if ((cipher_suites[u].req & REQ_TLS12) == 0
                || vmax >= BR_TLS12)
            {
                proto_ctx->suites[proto_ctx->num_suites ++] = cipher_suites[u];
            }
        }
    }
    if (hfuns == 0) {
        hfuns = (unsigned)-1;
    }
    if (iobuf_len == 0) {
        if (proto_ctx->bidi) {
            iobuf_len = BR_SSL_BUFSIZE_BIDI;
        } else {
            iobuf_len = BR_SSL_BUFSIZE_MONO;
        }
    }
    proto_ctx->iobuf = xmalloc(iobuf_len);

    /*
     * Compute implementation requirements and inject implementations.
     */
    proto_ctx->suite_ids = xmalloc((proto_ctx->num_suites + 1) * sizeof *(proto_ctx->suite_ids));
    br_ssl_client_zero(proto_ctx->cc);
    br_ssl_engine_set_versions(&proto_ctx->cc->eng, vmin, vmax);
    for (u = 0; hash_functions[u].name; u ++) {
        const br_hash_class *hc;
        int id;

        hc = hash_functions[u].hclass;
        id = (hc->desc >> BR_HASHDESC_ID_OFF) & BR_HASHDESC_ID_MASK;
        if ((hfuns & ((unsigned)1 << id)) != 0) {
            proto_ctx->dnhash = hc;
        }
    }
    if (proto_ctx->dnhash == NULL) {
        fprintf(stderr, "ERROR: no supported hash function\n");
        return ASIO_CB_ERR;
    }
    br_x509_minimal_init(proto_ctx->xc, proto_ctx->dnhash,
        &VEC_ELT(*(proto_ctx->anchors), 0), VEC_LEN(*(proto_ctx->anchors)));
    if (vmin <= BR_TLS11) {
        if (!(hfuns & (1 << br_md5_ID))) {
            fprintf(stderr, "ERROR: TLS 1.0 and 1.1 need MD5\n");
            return ASIO_CB_ERR;
        }
        if (!(hfuns & (1 << br_sha1_ID))) {
            fprintf(stderr, "ERROR: TLS 1.0 and 1.1 need SHA-1\n");
            return ASIO_CB_ERR;
        }
    }
    for (u = 0; u < proto_ctx->num_suites; u ++) {
        unsigned req;

        req = proto_ctx->suites[u].req;
        proto_ctx->suite_ids[u] = proto_ctx->suites[u].suite;
        if ((req & REQ_TLS12) != 0 && vmax < BR_TLS12) {
            fprintf(stderr,
                "ERROR: cipher suite %s requires TLS 1.2\n",
                proto_ctx->suites[u].name);
            return ASIO_CB_ERR;
        }
        if ((req & REQ_SHA1) != 0 && !(hfuns & (1 << br_sha1_ID))) {
            fprintf(stderr,
                "ERROR: cipher suite %s requires SHA-1\n",
                proto_ctx->suites[u].name);
            return ASIO_CB_ERR;
        }
        if ((req & REQ_SHA256) != 0 && !(hfuns & (1 << br_sha256_ID))) {
            fprintf(stderr,
                "ERROR: cipher suite %s requires SHA-256\n",
                proto_ctx->suites[u].name);
            return ASIO_CB_ERR;
        }
        if ((req & REQ_SHA384) != 0 && !(hfuns & (1 << br_sha384_ID))) {
            fprintf(stderr,
                "ERROR: cipher suite %s requires SHA-384\n",
                proto_ctx->suites[u].name);
            return ASIO_CB_ERR;
        }
        /* TODO: algorithm implementation selection */
        if ((req & REQ_AESCBC) != 0) {
            br_ssl_engine_set_default_aes_cbc(&proto_ctx->cc->eng);
        }
        if ((req & REQ_AESGCM) != 0) {
            br_ssl_engine_set_default_aes_gcm(&proto_ctx->cc->eng);
        }
        if ((req & REQ_CHAPOL) != 0) {
            br_ssl_engine_set_default_chapol(&proto_ctx->cc->eng);
        }
        if ((req & REQ_3DESCBC) != 0) {
            br_ssl_engine_set_default_des_cbc(&proto_ctx->cc->eng);
        }
        if ((req & REQ_RSAKEYX) != 0) {
            br_ssl_client_set_default_rsapub(proto_ctx->cc);
        }
        if ((req & REQ_ECDHE_RSA) != 0) {
            br_ssl_engine_set_default_ec(&proto_ctx->cc->eng);
            br_ssl_engine_set_default_rsavrfy(&proto_ctx->cc->eng);
        }
        if ((req & REQ_ECDHE_ECDSA) != 0) {
            br_ssl_engine_set_default_ecdsa(&proto_ctx->cc->eng);
        }
        if ((req & REQ_ECDH) != 0) {
            br_ssl_engine_set_default_ec(&proto_ctx->cc->eng);
        }
    }
    if (fallback) {
        proto_ctx->suite_ids[proto_ctx->num_suites ++] = 0x5600;
    }
    br_ssl_engine_set_suites(&proto_ctx->cc->eng, proto_ctx->suite_ids, proto_ctx->num_suites);

    for (u = 0; hash_functions[u].name; u ++) {
        const br_hash_class *hc;
        int id;

        hc = hash_functions[u].hclass;
        id = (hc->desc >> BR_HASHDESC_ID_OFF) & BR_HASHDESC_ID_MASK;
        if ((hfuns & ((unsigned)1 << id)) != 0) {
            br_ssl_engine_set_hash(&proto_ctx->cc->eng, id, hc);
            br_x509_minimal_set_hash(proto_ctx->xc, id, hc);
        }
    }
    if (vmin <= BR_TLS11) {
        br_ssl_engine_set_prf10(&proto_ctx->cc->eng, &br_tls10_prf);
    }
    if (vmax >= BR_TLS12) {
        if ((hfuns & ((unsigned)1 << br_sha256_ID)) != 0) {
            br_ssl_engine_set_prf_sha256(&proto_ctx->cc->eng,
                &br_tls12_sha256_prf);
        }
        if ((hfuns & ((unsigned)1 << br_sha384_ID)) != 0) {
            br_ssl_engine_set_prf_sha384(&proto_ctx->cc->eng,
                &br_tls12_sha384_prf);
        }
    }
    br_x509_minimal_set_rsa(proto_ctx->xc, br_rsa_pkcs1_vrfy_get_default());
    br_x509_minimal_set_ecdsa(proto_ctx->xc,
        br_ec_get_default(), br_ecdsa_vrfy_asn1_get_default());

    /*
     * If there is no provided trust anchor, then certificate validation
     * will always fail. In that situation, we use our custom wrapper
     * that tolerates unknown anchors.
     */
    if (VEC_LEN(*(proto_ctx->anchors)) == 0) {
        if (proto_ctx->verbose) {
            fprintf(stderr,
                "WARNING: no configured trust anchor\n");
        }
        x509_noanchor_init(proto_ctx->xwc, &proto_ctx->xc->vtable);
        br_ssl_engine_set_x509(&proto_ctx->cc->eng, &proto_ctx->xwc->vtable);
    } else {
        br_ssl_engine_set_x509(&proto_ctx->cc->eng, &proto_ctx->xc->vtable);
    }

    if (minhello_len != (size_t)-1) {
        br_ssl_client_set_min_clienthello_len(proto_ctx->cc, minhello_len);
    }
    br_ssl_engine_set_all_flags(&proto_ctx->cc->eng, flags);
    if (VEC_LEN(proto_ctx->alpn_names) != 0) {
        br_ssl_engine_set_protocol_names(&proto_ctx->cc->eng,
            (const char **)&VEC_ELT(proto_ctx->alpn_names, 0),
            VEC_LEN(proto_ctx->alpn_names));
    }

    if (proto_ctx->chain != NULL) {
        proto_ctx->zc->vtable = &ccert_vtable;
        proto_ctx->zc->verbose = proto_ctx->verbose;
        proto_ctx->zc->chain = proto_ctx->chain;
        proto_ctx->zc->chain_len = proto_ctx->chain_len;
        proto_ctx->zc->sk = proto_ctx->sk;
        if (nostaticecdh || proto_ctx->sk->key_type != BR_KEYTYPE_EC) {
            proto_ctx->zc->issuer_key_type = 0;
        } else {
            proto_ctx->zc->issuer_key_type = get_cert_signer_algo(&proto_ctx->chain[0]);
            if (proto_ctx->zc->issuer_key_type == 0) {
                return ASIO_CB_ERR;
            }
        }
        br_ssl_client_set_client_certificate(proto_ctx->cc, &proto_ctx->zc->vtable);
    }

    br_ssl_engine_set_buffer(&proto_ctx->cc->eng, proto_ctx->iobuf, iobuf_len, proto_ctx->bidi);
    br_ssl_client_reset(proto_ctx->cc, conn->url->host, 0);

    return ASIO_CB_OK;
}

asio_cb_res_t asio_ssl_close(asio_connection_t *conn)
{
    ESP_LOGI(TAG, "asio_ssl_handle_close");
    ssl_proto_ctx_t *proto_ctx = conn->io_ctx;

    xfree(proto_ctx->cc);
    xfree(proto_ctx->suites);
    xfree(proto_ctx->suite_ids);
    VEC_CLEAREXT(*proto_ctx->anchors, &free_ta_contents);
    VEC_CLEAREXT(proto_ctx->alpn_names, &free_alpn);
    free_certificates(proto_ctx->chain, proto_ctx->chain_len);
    free_private_key(proto_ctx->sk);
    xfree(proto_ctx->iobuf);
    if (conn->fd != INVALID_SOCKET) {
        close(conn->fd);
    }
    xfree(proto_ctx->zc);
    xfree(proto_ctx->xc);
    xfree(proto_ctx->xwc);
    xfree(proto_ctx->dnhash);
    xfree(proto_ctx->anchors);

    /* free delegate resources */
    proto_ctx->delegate_io_handler(conn, ASIO_EVT_CLOSE);

    return ASIO_CB_OK;
}


/* see brssl.h */
int
asio_ssl_run_engine(asio_connection_t *conn)
{
    ssl_proto_ctx_t *io_ctx = conn->io_ctx;
    br_ssl_engine_context *cc = &io_ctx->cc->eng;

    int verbose = io_ctx->verbose;
    int trace = io_ctx->trace;

    /* poll socket */
    if(conn->poll_handler(conn) == ASIO_POLL_ERR) {
        ESP_LOGE(TAG, "poll failed");
        conn->user_flags |= CONN_FLAG_CLOSE;
        return 0;
    }

    /*
     * Perform the loop.
     */
    unsigned st;
    int sendrec, recvrec, sendapp, recvapp;
    int sendrec_ok, recvrec_ok, sendapp_ok, recvapp_ok;

    /*
     * Get current engine state.
     */
    st = br_ssl_engine_current_state(cc);
    if (st == BR_SSL_CLOSED) {
        handle_closed(verbose, cc);
        conn->user_flags |= CONN_FLAG_CLOSE;
        return ASIO_CB_CLOSE_CONNECTION;
    }

    /*
     * Compute descriptors that must be polled, depending
     * on engine state.
     */
    sendrec = ((st & BR_SSL_SENDREC) != 0);
    recvrec = ((st & BR_SSL_RECVREC) != 0);
    sendapp = ((st & BR_SSL_SENDAPP) != 0);
    recvapp = ((st & BR_SSL_RECVAPP) != 0);

    if (verbose && sendapp && !io_ctx->hsdetails) {
        print_handshake_result(cc);
        io_ctx->hsdetails = 1;
    }

    /*
     * We transform closures/errors into read+write accesses
     * so as to force the read() or write() call that will
     * detect the situation.
     */
    /*
    while (u -- > 0) {
        if (pfd[u].revents & (POLLERR | POLLHUP)) {
            pfd[u].revents |= POLLIN | POLLOUT;
        }
    }
    */

    recvapp_ok = recvapp;
    sendrec_ok = sendrec && (conn->poll_flags & POLL_FLAG_SEND);
    recvrec_ok = recvrec && (conn->poll_flags & POLL_FLAG_RECV);
    sendapp_ok = sendapp;

    // ESP_LOGI(TAG, "recvapp_ok %d sendrec_ok %d recvrec_ok %d sendapp_ok %d", recvapp_ok, sendrec_ok, recvrec_ok, sendapp_ok);

    /*
     * We give preference to outgoing data, on stdout and on
     * the socket.
     */

    /* write app data */
    if (recvapp_ok) {
        unsigned char *buf;
        size_t len;
        ssize_t wlen;

        buf = br_ssl_engine_recvapp_buf(cc, &len);
        // write directly to upper proto
        wlen = conn->app_recv(conn, buf, len);
        if(wlen >= 0) {
            br_ssl_engine_recvapp_ack(cc, wlen);
        } else {
            br_ssl_engine_recvapp_ack(cc, 0);
            ESP_LOGI(TAG, "app_recv error");
        }

        if(trace) {
            ESP_LOGI(TAG, "wrote %d bytes to app", wlen);
        }
    }

    /* write to socket */
    if (sendrec_ok) {
        unsigned char *buf;
        size_t len;
        int wlen;

        buf = br_ssl_engine_sendrec_buf(cc, &len);
        wlen = send(conn->fd, buf, len, 0);
        if(trace) {
            ESP_LOGI(TAG, "wrote %d bytes to socket", wlen);
        }
        if (wlen <= 0) {

            if (errno == EINTR || errno == EWOULDBLOCK) {
                // OK
            }

            if (verbose) {
                fprintf(stderr, "socket closed...\n");
            }
            conn->user_flags |= CONN_FLAG_CLOSE;
            return ASIO_CB_CLOSE_CONNECTION;
        }
        if (trace) {
            dump_blob("Outgoing bytes", buf, wlen);
        }
        br_ssl_engine_sendrec_ack(cc, wlen);
    }

    /* read from socket */
    if (recvrec_ok) {
        unsigned char *buf;
        size_t len;
        int rlen;

        buf = br_ssl_engine_recvrec_buf(cc, &len);
        rlen = recv(conn->fd, buf, len, 0);
        if(trace) {
            ESP_LOGI(TAG, "read %d bytes from socket", rlen);
        }
        if (rlen <= 0) {

            if (errno == EINTR || errno == EWOULDBLOCK) {
                // OK
                ESP_LOGI(TAG, "EINTR || EWOULDBLOCK");
            }

            if (verbose) {
                fprintf(stderr, "socket closed...\n");
            }

            conn->user_flags |= CONN_FLAG_CLOSE;
            return ASIO_CB_CLOSE_CONNECTION;
        }
        if (trace) {
            dump_blob("Incoming bytes", buf, rlen);
        }
        br_ssl_engine_recvrec_ack(cc, rlen);
    }

    /* read app data */

    if (sendapp_ok) {
        unsigned char *buf;
        size_t len;
        ssize_t rlen;

        buf = br_ssl_engine_sendapp_buf(cc, &len);
        rlen = conn->app_send(conn, buf, len);
        if(trace) {
            ESP_LOGI(TAG, "read %d bytes from app:\n%.*s", rlen, rlen, buf);
        }

        if (rlen < 0) {
            if (verbose) {
                fprintf(stderr, "app closed...\n");
            }
            br_ssl_engine_close(cc);
        } else if (!run_command(cc, buf, rlen)) {
            br_ssl_engine_sendapp_ack(cc, rlen);
        }
        br_ssl_engine_flush(cc, 0);
    }

    return ASIO_CB_OK;
}

asio_cb_res_t asio_io_handler_ssl(asio_connection_t *conn, asio_event_t event)
{
    switch (event) {
        case ASIO_EVT_NEW:
            return asio_ssl_connect(conn, event);
            break;

        case ASIO_EVT_CONNECTED:
            break;

        case ASIO_EVT_SOCKET_READY:
            return asio_ssl_run_engine(conn);
            break;

        case ASIO_EVT_CLOSE:
            return asio_ssl_close(conn);
            break;
    }

    return ASIO_CB_OK;
}


asio_connection_t *asio_new_ssl_connection(asio_registry_t *registry, asio_transport_t transport_proto, char *uri, int bidi, char *alpn, cipher_suite *suites, size_t num_suites, void *user_data)
{

    asio_connection_t *conn = asio_new_socket_connection(registry, ASIO_TCP, uri, user_data);

    ssl_proto_ctx_t *io_ctx = calloc(1, sizeof(ssl_proto_ctx_t));
    conn->io_ctx = io_ctx;

    // chain io handler
    io_ctx->delegate_io_handler = conn->io_handler;
    conn->io_handler = asio_io_handler_ssl;

    io_ctx->verbose = 1;
    io_ctx->trace = 0;
    io_ctx->cc = calloc(1, sizeof(*(io_ctx->cc)));
    io_ctx->zc = calloc(1, sizeof(*(io_ctx->zc)));
    io_ctx->xc = calloc(1, sizeof(*(io_ctx->xc)));
    io_ctx->xwc = calloc(1, sizeof(*(io_ctx->xwc)));
    io_ctx->bidi = bidi;
    if(alpn != NULL)
        VEC_ADD(io_ctx->alpn_names, xstrdup(alpn));

    io_ctx->anchors = calloc(1, sizeof(*(io_ctx->anchors)));

    /*
     * Print algorithm details.
     */
    if (io_ctx->verbose) {
        print_algos(&io_ctx->cc->eng);
    }

    return conn;
}
