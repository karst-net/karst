/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Copyright the Karst contributors. */

/*
 * Hand-written, not cbindgen-generated — see crates/karst-embed-capi's own
 * crate-level doc comment (src/lib.rs) for why, and
 * docs/adr/0044-embedded-library-mode.md for the decision this records.
 * This header must be kept in sync with src/lib.rs's #[no_mangle] functions
 * by hand; a mismatch here is a linker or runtime bug, not a compile error.
 *
 * GitHub issue #214.
 */

#ifndef KARST_EMBED_CAPI_H
#define KARST_EMBED_CAPI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque handles. Every one is a boxed Rust value behind a raw pointer —
 * never dereference the pointer itself from C/Go, only pass it back to the
 * functions below.
 *
 * Free-ordering contract (stated once, applies throughout): a
 * karst_embed_tcp_stream_t, karst_embed_tcp_listener_t, or
 * karst_embed_udp_socket_t borrows the karst_embed_node_t it came from. Free
 * every stream, listener, and UDP socket derived from a node *before*
 * calling karst_embed_free on that node. Using a stream/listener/socket
 * handle after its node has been freed is undefined behavior — nothing here
 * detects it.
 */
typedef struct karst_embed_node karst_embed_node_t;
typedef struct karst_embed_tcp_stream karst_embed_tcp_stream_t;
typedef struct karst_embed_tcp_listener karst_embed_tcp_listener_t;
typedef struct karst_embed_udp_socket karst_embed_udp_socket_t;

/*
 * The most recent error on the calling thread, or NULL if the last call did
 * not fail. Valid only until the next karst_embed_* call on this thread, and
 * must not be freed — copy it (e.g. with C.GoString in cgo) before making
 * another call.
 */
const char *karst_embed_last_error(void);

/* Free a string this library returned (e.g. from karst_embed_status_json or
 * an out-parameter). A no-op on NULL. */
void karst_embed_free_string(char *s);

/* Free a byte buffer karst_embed_udp_recv_from returned. A no-op on NULL. */
void karst_embed_free_bytes(uint8_t *buf, size_t len);

/*
 * Provision this node from a pasted administrator invitation.
 * Returns 0 on success, -1 on error (see karst_embed_last_error).
 */
int32_t karst_embed_enroll(const char *invitation, const char *config_path,
                            const char *state_dir);

/* As karst_embed_enroll, but explicitly replaces an existing configuration
 * instead of refusing. */
int32_t karst_embed_re_enroll(const char *invitation, const char *config_path,
                               const char *state_dir);

/*
 * Load config_path (already written by karst_embed_enroll/_re_enroll) and
 * start the embedded engine on a background thread. config_path's
 * network_mode must already be "userspace". Returns NULL on error.
 *
 * socket_path is this process's own private control socket; nothing outside
 * it needs to reach it.
 */
karst_embed_node_t *karst_embed_start(const char *config_path,
                                       const char *socket_path);

/* Ask the node to stop, and block until it actually does. Does not free
 * node — call karst_embed_free afterward (which also calls this). A no-op
 * on NULL. */
void karst_embed_stop(karst_embed_node_t *node);

/* Stop (if not already) and free a node. Every stream, listener, and UDP
 * socket derived from it must already be freed — see the free-ordering
 * contract above. A no-op on NULL. node must not be used again after this
 * call. */
void karst_embed_free(karst_embed_node_t *node);

/* This node's own status, as JSON. Returns NULL on error. The caller must
 * free the result with karst_embed_free_string. */
char *karst_embed_status_json(karst_embed_node_t *node);

/* Open a TCP connection to another mesh peer's overlay address. Returns NULL
 * on error. */
karst_embed_tcp_stream_t *karst_embed_tcp_connect(karst_embed_node_t *node,
                                                   const char *address,
                                                   uint16_t port);

/* Listen for inbound TCP connections on an overlay port. Returns NULL on
 * error. */
karst_embed_tcp_listener_t *karst_embed_tcp_listen(karst_embed_node_t *node,
                                                    uint16_t port);

/*
 * Block until a peer connects. out_peer_address/out_peer_port, if non-NULL,
 * receive the peer's overlay address — *out_peer_address is a newly
 * allocated string the caller must free with karst_embed_free_string.
 * Returns NULL on error.
 */
karst_embed_tcp_stream_t *
karst_embed_tcp_accept(karst_embed_tcp_listener_t *listener,
                        char **out_peer_address, uint16_t *out_peer_port);

/*
 * Read up to len bytes into buf. Returns the number of bytes read (0 means
 * the peer closed its sending half), or -1 on error.
 */
int64_t karst_embed_tcp_read(karst_embed_tcp_stream_t *stream, uint8_t *buf,
                              size_t len);

/*
 * Write up to len bytes from buf. Returns the number of bytes written, or
 * -1 on error (including the connection no longer being active).
 */
int64_t karst_embed_tcp_write(karst_embed_tcp_stream_t *stream,
                               const uint8_t *buf, size_t len);

/* Free a TCP stream, releasing its underlying overlay socket. A no-op on
 * NULL. */
void karst_embed_tcp_stream_free(karst_embed_tcp_stream_t *stream);

/* Free a TCP listener, releasing its underlying overlay socket. A no-op on
 * NULL. */
void karst_embed_tcp_listener_free(karst_embed_tcp_listener_t *listener);

/* Bind a UDP socket on an overlay port. Returns NULL on error. */
karst_embed_udp_socket_t *karst_embed_udp_bind(karst_embed_node_t *node,
                                                uint16_t port);

/* Send one datagram to a peer's overlay address. Returns 0 on success, -1
 * on error. */
int32_t karst_embed_udp_send_to(karst_embed_udp_socket_t *sock,
                                 const uint8_t *buf, size_t len,
                                 const char *to_address, uint16_t to_port);

/*
 * Block until a datagram arrives. *out_buf/*out_len receive a newly
 * allocated byte buffer the caller must free with karst_embed_free_bytes;
 * out_from_address/out_from_port, if non-NULL, receive the sender's overlay
 * address — *out_from_address is a newly allocated string the caller must
 * free with karst_embed_free_string. Returns 0 on success, -1 on error.
 */
int32_t karst_embed_udp_recv_from(karst_embed_udp_socket_t *sock,
                                   uint8_t **out_buf, size_t *out_len,
                                   char **out_from_address,
                                   uint16_t *out_from_port);

/* Free a UDP socket, releasing its underlying overlay socket. A no-op on
 * NULL. */
void karst_embed_udp_socket_free(karst_embed_udp_socket_t *sock);

#ifdef __cplusplus
}
#endif

#endif /* KARST_EMBED_CAPI_H */
