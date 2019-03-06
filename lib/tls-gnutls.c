/* vim: set tabstop=8 shiftwidth=2 softtabstop=2 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2018 Red Hat, Inc.
 *
 * Author: Nathaniel McCallum
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "core.h"
#include "locks.h"
#include "tls.h"
#include "tlssock.h"

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#define NUM_CERTS_INIT 16

struct tls {
  rwlock_t *lock;
  size_t ref;

  gnutls_session_t session;

  struct {
    union {
      struct {
        gnutls_psk_client_credentials_t psk;
        gnutls_certificate_credentials_t cert;
      } clt;

      struct {
        gnutls_psk_server_credentials_t psk;
        gnutls_certificate_credentials_t cert;
      } srv;
    };
  } creds;
};

static inline int
g2e(int ret)
{
  switch (ret) {
  case GNUTLS_E_SUCCESS:
    return 0;

  case GNUTLS_E_AGAIN:
    errno = EAGAIN;
    return -1;

  case GNUTLS_E_INTERRUPTED:
    errno = EINTR;
    return -1;

  case GNUTLS_E_LARGE_PACKET:
    errno = EMSGSIZE;
    return -1;

  case GNUTLS_E_INSUFFICIENT_CREDENTIALS:
    errno = EACCES; // FIXME
    return -1;

  default:
    if (!gnutls_error_is_fatal(ret))
      return ret;

    errno = EIO; // FIXME
    return -1;
  }
}

static inline void
destroy_if_set(void *target, size_t len)
{
  if (target != NULL) {
    explicit_bzero(target, len);
    free(target);
  }
}

static inline void
destroy_str_if_set(char *target)
{
  if (target != NULL) {
    explicit_bzero(target, strlen(target));
    free(target);
  }
}

tls_t *
tls_new(void)
{
  tls_t *tls = NULL;

  tls = calloc(1, sizeof(*tls));
  if (!tls)
    return NULL;

  tls->lock = rwlock_init();
  if (!tls->lock) {
    free(tls);
    return NULL;
  }

  tls->ref = 1;
  return tls;
}

void
tls_cleanup(tls_t **tls)
{
  if (tls)
    tls_decref(*tls);
}

tls_t *
tls_incref(tls_t *tls)
{
  if (!tls)
    return NULL;
  {
    rwhold_auto_t *hold = rwlock_wrlock(tls->lock);
    if (!hold)
      return NULL;

    tls->ref++;
  }

  return tls;
}

static void
tls_creds_clear(tls_t *tls, bool client)
{
  if (tls->session)
    gnutls_credentials_clear(tls->session);

  if (client) {
    if (tls->creds.clt.psk)
      gnutls_psk_free_client_credentials(tls->creds.clt.psk);
    if (tls->creds.clt.cert)
      gnutls_certificate_free_credentials(tls->creds.clt.cert);
    tls->creds.clt.psk = NULL;
    tls->creds.clt.cert = NULL;
  } else {
    if (tls->creds.srv.psk)
      gnutls_psk_free_server_credentials(tls->creds.srv.psk);
    if (tls->creds.srv.cert)
      gnutls_certificate_free_credentials(tls->creds.srv.cert);
    tls->creds.srv.psk = NULL;
    tls->creds.srv.cert = NULL;
  }
}

static void
tls_clear(tls_t *tls)
{
  if (!tls || !tls->session)
    return;

  tls_creds_clear(tls, gnutls_session_get_flags(tls->session) & GNUTLS_CLIENT);
  gnutls_deinit(tls->session);
  tls->session = NULL;
}

tls_t *
tls_decref(tls_t *tls)
{
  if (!tls)
    return NULL;

  {
    rwhold_auto_t *hold = rwlock_wrlock(tls->lock);
    if (!hold)
      return NULL;

    if (tls->ref-- > 1)
      return tls;

    tls_clear(tls);
  }

  rwlock_free(tls->lock);
  memset(tls, 0, sizeof(*tls));
  return NULL;
}

ssize_t
tls_read(tls_t *tls, int fd, void *buf, size_t count)
{
  rwhold_auto_t *hold = rwlock_rdlock(tls->lock);
  return g2e(gnutls_record_recv(tls->session, buf, count));
}

ssize_t
tls_write(tls_t *tls, int fd, const void *buf, size_t count)
{
  rwhold_auto_t *hold = rwlock_rdlock(tls->lock);
  return g2e(gnutls_record_send(tls->session, buf, count));
}

static int
tls_getsockopt_peer_subject_dn(tls_t *tls, void *optval, socklen_t *optlen)
{
  int ret;
  gnutls_x509_crt_t crt;
  const gnutls_datum_t *cert_list;
  unsigned int cert_list_size = 0;
  gnutls_datum_t dn = {NULL, 0};

  cert_list = gnutls_certificate_get_peers(tls->session, &cert_list_size);
  if (cert_list_size == 0) {
    strncpy(optval, "(no subject)", *optlen);
    *optlen = strlen(optval);
    return 0;
  }

  ret = gnutls_x509_crt_init(&crt);
  if (ret < 0) {
    errno = EFAULT;  // TODO
    goto cleanup;
  }

  ret = gnutls_x509_crt_import(crt, &cert_list[0], GNUTLS_X509_FMT_DER);
  if (ret < 0) {
    errno = EINVAL;  // TODO
    goto cleanup;
  }

  ret = gnutls_x509_crt_get_dn3(crt, &dn, 0);
  if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
    strncpy(optval, "(no subject)", *optlen);
    *optlen = strlen(optval);
    ret = 0;
    goto cleanup;
  }
  if (ret < 0) {
    errno = EINVAL;  // TODO
    goto cleanup;
  }

  if ((dn.size+1) < *optlen)
    *optlen = dn.size+1;

  memcpy(optval, dn.data, *optlen);
  ((char*)optval)[*optlen] = '\0';

cleanup:
  gnutls_x509_crt_deinit(crt);
  return ret;
}

int
tls_getsockopt(tls_t *tls, int fd, int optname, void *optval, socklen_t *optlen)
{
  switch(optname) {
  case TLS_OPT_PEER_SUBJECT_DN:
    return tls_getsockopt_peer_subject_dn(tls, optval, optlen);
  default:
    errno = ENOPROTOOPT;
    return -1;
  }
}

static ssize_t
pull_func(gnutls_transport_ptr_t ptr, void *buf, size_t count)
{
  return NEXT(read)((intptr_t) ptr, buf, count);
}

static ssize_t
push_func(gnutls_transport_ptr_t ptr, const void *buf, size_t count)
{
  return NEXT(write)((intptr_t) ptr, buf, count);
}

static ssize_t
vec_push_func(gnutls_transport_ptr_t ptr, const giovec_t *iov, int iovcnt)
{
  return NEXT(writev)((intptr_t) ptr, iov, iovcnt);
}

static int
pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms)
{
  struct pollfd pfd = { (intptr_t) ptr, POLLIN | POLLPRI };
  int timeout = 0;

  if (ms == GNUTLS_INDEFINITE_TIMEOUT)
    timeout = -1;
  else if (ms > INT_MAX)
    timeout = INT_MAX;
  else
    timeout = ms;

  return poll(&pfd, 1, timeout);
}

static int
get_flags(int fd, bool client)
{
  int flags = client ? GNUTLS_CLIENT : GNUTLS_SERVER;
  int type = 0;
  int ret = 0;

  ret = fcntl(fd, F_GETFL);
  if (ret < 0)
    return ret;
  if (ret & O_NONBLOCK)
    flags |= GNUTLS_NONBLOCK;

  if (getsockopt_int(fd, SOL_SOCKET, SO_TYPE, &type) < 0)
    return -1;
  if (type == SOCK_DGRAM)
    flags |= GNUTLS_DATAGRAM;

  return flags;
}

static int
psk_clt(gnutls_session_t session, char **username, gnutls_datum_t *key)
{
  const tls_handshake_t *hs = gnutls_session_get_ptr(session);
  uint8_t *k = NULL;
  char *u = NULL;
  ssize_t l = 0;

  l = hs->clt.psk(hs->clt.misc, &u, &k);
  if (l < 0)
    return -1;

  *username = gnutls_strdup(u);
  key->data = gnutls_malloc(l);
  key->size = l;
  if (key->data)
    memcpy(key->data, k, l);

  explicit_bzero(u, strlen(u));
  explicit_bzero(k, l);
  free(u);
  free(k);

  if (*username && key->data)
    return 0;

  destroy_str_if_set(*username);
  destroy_if_set(key->data, l);

  return -1;
}

static int
psk_srv(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
  const tls_handshake_t *hs = gnutls_session_get_ptr(session);
  uint8_t *k = NULL;
  ssize_t l = 0;

  l = hs->srv.psk(hs->srv.misc, username, &k);
  if (l < 0)
    return -1;

  key->data = gnutls_malloc(l);
  key->size = l;
  if (key->data)
    memcpy(key->data, k, l);

  explicit_bzero(k, l);
  free(k);

  return key->data ? 0 : -1;
}

static int
pin_cb(void *userdata, int attempt, const char *token_url,
       const char *token_label, unsigned int flags, char *pin, size_t pin_max)
{
  const char *p = userdata;

  if (attempt > 0)
    return -1;
  if (p == NULL)
    return -1;
  if (strlen(p) >= pin_max)
    return -1;
  strncpy(pin, p, pin_max);
  return 0;
}

static inline void
clear_plist(gnutls_pcert_st *list, unsigned int length)
{
  for (unsigned int i = 0; i < length; i++)
    gnutls_pcert_deinit(&list[i]);
}

static int
load_certificate(gnutls_session_t session, gnutls_pcert_st **pcert,
                 unsigned int *pcert_length, gnutls_privkey_t *pkey,
                 const char *cert_uri, const char *key_uri, const char *pin)
{
  gnutls_pcert_st *p = NULL;
  gnutls_privkey_t k = NULL;
  unsigned int cert_size = NUM_CERTS_INIT;
  gnutls_datum_t keydata = {NULL, 0};
  int ret;

  p = gnutls_malloc(NUM_CERTS_INIT * sizeof(gnutls_pcert_st));
  if (!p) {
    ret = GNUTLS_E_MEMORY_ERROR;
    goto out;
  }
  ret = gnutls_pcert_list_import_x509_file(
    p,
    &cert_size,
    cert_uri,
    GNUTLS_X509_FMT_PEM,
    pin_cb,
    (void*)pin,
    GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED | GNUTLS_X509_CRT_LIST_SORT);
  if (ret < 0)
    goto out;

  ret = gnutls_privkey_init(&k);
  if (ret < 0)
    goto out;

  if (gnutls_url_is_supported(key_uri)) {
    // PKCS11
    ret = gnutls_privkey_import_url(k, key_uri, 0);
  } else {
    // File path
    ret = gnutls_load_file(key_uri, &keydata);
    if (ret < 0)
      goto out;
    ret = gnutls_privkey_import_x509_raw(k,
                                         &keydata,
                                         GNUTLS_X509_FMT_PEM,
                                         pin,
                                         0);
    if (ret < 0)
      goto out;
  }

  *pcert = p;
  *pcert_length = cert_size;
  *pkey = k;

out:
  explicit_bzero(keydata.data, keydata.size);
  gnutls_free(keydata.data);

  if (ret != 0) {
    if (p != NULL) {
      clear_plist(p, cert_size);
      free(p);
    }
    if (k != NULL) {
      gnutls_privkey_deinit(k);
    }
  }
  return ret;
}

static int
cert_srv(gnutls_session_t session, const gnutls_datum_t *req_ca_dn, int nreqs,
         const gnutls_pk_algorithm_t *pk_algos, int pk_algos_length,
         gnutls_pcert_st **pcert, unsigned int *pcert_length,
         gnutls_privkey_t *pkey)
{
  const tls_handshake_t *hs = gnutls_session_get_ptr(session);
  char *cert_uri = NULL;
  char *key_uri = NULL;
  char *pin = NULL;
  int ret = 0;
  /* DNS names (only type supported) may be at most 256 bytes long */
  char *servername;
  size_t namelen = 256;
  unsigned int nametype;

  servername = gnutls_malloc(namelen);
  if (servername == NULL)
    return GNUTLS_E_MEMORY_ERROR;

  for (int i = 0; ; i++) {
    ret = gnutls_server_name_get(session, servername, &namelen, &nametype, i);
    if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
      /* We hit no NAME_DNS before the end, so no servername we can use.
       * But that might be fine. */
      free(servername);
      servername = NULL;
      break;
    }
    if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
      continue;  // This must not be DNS, or an invalid DNS name. Ignore
    if (ret != GNUTLS_E_SUCCESS)
      goto out;
    if (nametype != GNUTLS_NAME_DNS)
      continue;
    /* This was a correctly retrieved DNS name. Per RFC6066, section 3, that
       means there are no more DNS names in this request. Send this forward. */
    break;
  }

  ret = hs->srv.cert.getcert(hs->srv.misc,
                             servername,
                             &cert_uri,
                             &key_uri,
                             &pin);
  if (ret < 0)
    goto out;

  ret = load_certificate(session,
                         pcert,
                         pcert_length,
                         pkey,
                         cert_uri,
                         key_uri,
                         pin);

out:
  if (servername != NULL) {
    free(servername);
  }
  destroy_str_if_set(cert_uri);
  destroy_str_if_set(key_uri);
  destroy_str_if_set(pin);
  return ret;
}

static int
cert_clt(gnutls_session_t session, const gnutls_datum_t *req_ca_dn, int nreqs,
         const gnutls_pk_algorithm_t *pk_algos, int pk_algos_length,
         gnutls_pcert_st **pcert, unsigned int *pcert_length,
         gnutls_privkey_t *pkey)
{
  const tls_handshake_t *hs = gnutls_session_get_ptr(session);
  char *cert_uri = NULL;
  char *key_uri = NULL;
  char *pin = NULL;
  int ret = 0;
  char **req_ca_dn_strs;
  gnutls_datum_t ca_dn = {NULL, 0};

  req_ca_dn_strs = gnutls_malloc(sizeof(char *) * (nreqs + 1));

  if (req_ca_dn_strs == NULL) {
    ret = GNUTLS_E_MEMORY_ERROR;
    goto out;
  }

  for (int i = 0; i < nreqs; i++) {
    ret = gnutls_x509_rdn_get2(&req_ca_dn[i], &ca_dn, 0);
    if (ret < 0)
      goto out;
    req_ca_dn_strs[i] = gnutls_malloc(sizeof(char) * (ca_dn.size + 1));
    if (req_ca_dn_strs[i] == NULL) {
      ret = GNUTLS_E_MEMORY_ERROR;
      goto out;
    }
    memcpy(req_ca_dn_strs[i], ca_dn.data, ca_dn.size);
    req_ca_dn_strs[i][ca_dn.size] = '\0';
  }
  req_ca_dn_strs[nreqs+1] = NULL;

  ret = hs->clt.cert.getcert(hs->clt.misc,
                             (const char **)req_ca_dn_strs,
                             &cert_uri,
                             &key_uri,
                             &pin);
  if (ret < 0)
    goto out;

  ret = load_certificate(session,
                         pcert,
                         pcert_length,
                         pkey,
                         cert_uri,
                         key_uri,
                         pin);

out:
  destroy_if_set(ca_dn.data, ca_dn.size);
  if (req_ca_dn_strs != NULL) {
    for(int i = 0; i < nreqs; i++) {
      if (req_ca_dn_strs[i] != NULL)
        free(req_ca_dn_strs[i]);
    }
    free(req_ca_dn_strs);
  }
  destroy_str_if_set(cert_uri);
  destroy_str_if_set(key_uri);
  destroy_str_if_set(pin);
  return ret;
}

static int
cert_verify(gnutls_session_t session, const char *hostname, const char *purpose,
            int optional)
{
  int ret;
  unsigned int status = 0;
  gnutls_typed_vdata_st data[2];
  unsigned elements = 0;

  memset(data, 0, sizeof(data));

  if (hostname) {
    data[elements].type = GNUTLS_DT_DNS_HOSTNAME;
    data[elements].data = (void*)hostname;
    elements++;
  }

  if (purpose) {
    data[elements].type = GNUTLS_DT_KEY_PURPOSE_OID;
    data[elements].data = (void*)purpose;
    elements++;
  }

  ret = gnutls_certificate_verify_peers(session, data, elements, &status);
  if (ret == GNUTLS_E_NO_CERTIFICATE_FOUND && optional)
    return 0;
  if (ret != GNUTLS_E_SUCCESS)
    return ret;
  return status;
}

static int
cert_verify_srv(gnutls_session_t session)
{
  const tls_handshake_t *hs = gnutls_session_get_ptr(session);
  int optional = 1;
  if (hs->srv.cert.client_certificate_request == 2)
    optional = 0;
  return cert_verify(session, NULL, GNUTLS_KP_TLS_WWW_CLIENT, optional);
}

static int
cert_verify_clt(gnutls_session_t session)
{
  const tls_handshake_t *hs = gnutls_session_get_ptr(session);
  return cert_verify(session,
                     hs->clt.cert.hostname,
                     GNUTLS_KP_TLS_WWW_SERVER,
                     0);
}

int
tls_handshake(tls_t *tls, int fd, bool client, const tls_handshake_t *hs)
{
  int ret = -1;

  if (!tls->session) {
    static const char *priority = "+ECDHE-PSK:+DHE-PSK:+PSK";
    int flags = 0;

    flags = get_flags(fd, client);
    if (flags < 0)
      return flags;

    ret = g2e(gnutls_init(&tls->session, flags));
    if (ret < 0)
      return ret;

    gnutls_transport_set_int(tls->session, fd);
    gnutls_transport_set_pull_function(tls->session, pull_func);
    gnutls_transport_set_push_function(tls->session, push_func);
    gnutls_transport_set_vec_push_function(tls->session, vec_push_func);
    gnutls_transport_set_pull_timeout_function(tls->session, pull_timeout_func);
    gnutls_handshake_set_timeout(tls->session, 0);

    ret = g2e(gnutls_set_default_priority_append(tls->session, priority, NULL, 0));
    if (ret < 0)
      goto error;
  }

  if (client) {
    if (hs->clt.psk) {
      ret = g2e(gnutls_psk_allocate_client_credentials(&tls->creds.clt.psk));
      if (ret < 0)
        goto error;

      gnutls_psk_set_client_credentials_function(tls->creds.clt.psk, psk_clt);
      ret = g2e(gnutls_credentials_set(tls->session, GNUTLS_CRD_PSK,
                                      tls->creds.clt.psk));
      if (ret < 0)
        goto error;
    } else {  // Client-side certificates
      ret = g2e(gnutls_certificate_allocate_credentials(&tls->creds.clt.cert));
      if (ret < 0)
        goto error;

      if (hs->clt.cert.hostname) {
        ret = gnutls_server_name_set(tls->session,
                                     GNUTLS_NAME_DNS,
                                     hs->clt.cert.hostname,
                                     strlen(hs->clt.cert.hostname));
        if (ret < 0) {
          ret = g2e(ret);
          goto error;
        }
      }
      if (hs->clt.cert.getcert) {
        gnutls_certificate_set_retrieve_function2(tls->creds.clt.cert,
                                                  cert_clt);
      }
      if (hs->clt.cert.cafile != NULL) {
        ret = gnutls_certificate_set_x509_trust_file(tls->creds.clt.cert,
                                                     hs->clt.cert.cafile,
                                                     GNUTLS_X509_FMT_PEM);
        if (ret < 0) {
          ret = g2e(ret);
          goto error;
        }
      } else {
        if (hs->clt.cert.insecure == 0) {
          ret = gnutls_certificate_set_x509_system_trust(tls->creds.srv.cert);
          if (ret < 0) {
            ret = g2e(ret);
            goto error;
          }
        }
      }
      gnutls_certificate_set_verify_function(tls->creds.clt.cert, cert_verify_clt);
      ret = gnutls_credentials_set(tls->session, GNUTLS_CRD_CERTIFICATE,
                                   tls->creds.clt.cert);
      ret = g2e(ret);
    }
  } else {  // Server
    if (hs->srv.psk) {
      ret = gnutls_psk_allocate_server_credentials(&tls->creds.srv.psk);
      if (ret < 0) {
        ret = g2e(ret);
        goto error;
      }

      gnutls_psk_set_server_credentials_function(tls->creds.srv.psk, psk_srv);
      ret = gnutls_credentials_set(tls->session, GNUTLS_CRD_PSK,
                                   tls->creds.srv.psk);
      if (ret < 0) {
        ret = g2e(ret);
        goto error;
      }
    } else {  // Server-side certificate
      ret = gnutls_certificate_allocate_credentials(&tls->creds.srv.cert);
      if (ret < 0) {
        ret = g2e(ret);
        goto error;
      }

      if (hs->srv.cert.getcert) {
        gnutls_certificate_set_retrieve_function2(tls->creds.srv.cert,
                                                  cert_srv);
      }

      switch (hs->srv.cert.client_certificate_request) {
      case TLS_CLIENT_CERT_IGNORE:
        gnutls_certificate_server_set_request(tls->session,
                                              GNUTLS_CERT_IGNORE);
        break;
      case TLS_CLIENT_CERT_REQUEST:
        gnutls_certificate_server_set_request(tls->session,
                                              GNUTLS_CERT_REQUEST);
        break;
      case TLS_CLIENT_CERT_REQUIRE:
        // Fallthrough: anything >=2 we assume means "require client cert"
        //  so we fail closed
      default:
        gnutls_certificate_server_set_request(tls->session,
                                              GNUTLS_CERT_REQUIRE);
        break;
      }

      if (hs->srv.cert.cafile != NULL) {
        ret = gnutls_certificate_set_x509_trust_file(tls->creds.srv.cert,
                                                         hs->srv.cert.cafile,
                                                         GNUTLS_X509_FMT_PEM);
        if (ret < 0) {
          ret = g2e(ret);
          goto error;
        }
      } else {
        if (hs->srv.cert.insecure == 0) {
          ret = gnutls_certificate_set_x509_system_trust(tls->creds.srv.cert);
          if (ret < 0) {
            ret = g2e(ret);
            goto error;
          }
        }
      }
      gnutls_certificate_set_verify_function(tls->creds.srv.cert, cert_verify_srv);
      ret = gnutls_credentials_set(tls->session, GNUTLS_CRD_CERTIFICATE,
                                   tls->creds.srv.cert);
      ret = g2e(ret);
    }
  }

  gnutls_session_set_ptr(tls->session, (void *) hs);
  ret = g2e(gnutls_handshake(tls->session));
  gnutls_session_set_ptr(tls->session, NULL);
  tls_creds_clear(tls, client);
  if (ret >= 0 || errno == EAGAIN)
    return ret;

error:
  tls_clear(tls);
  return ret;
}
