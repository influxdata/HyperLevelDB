/* Copyright (c) 2011 The LevelDB Authors. All rights reserved.
  Use of this source code is governed by a BSD-style license that can be
  found in the LICENSE file. See the AUTHORS file for names of contributors.

  C bindings for hyperleveldb.  May be useful as a stable ABI that can be
  used by programs that keep hyperleveldb in a shared library, or for
  a JNI api.

  Does not support:
  . getters for the option types
  . custom comparators that implement key shortening
  . custom iter, db, env, cache implementations using just the C bindings

  Some conventions:

  (1) We expose just opaque struct pointers and functions to clients.
  This allows us to change internal representations without having to
  recompile clients.

  (2) For simplicity, there is no equivalent to the Slice type.  Instead,
  the caller has to pass the pointer and length as separate
  arguments.

  (3) Errors are represented by a null-terminated c string.  NULL
  means no error.  All operations that can raise an error are passed
  a "char** errptr" as the last argument.  One of the following must
  be true on entry:
     *errptr == NULL
     *errptr points to a malloc()ed null-terminated error message
       (On Windows, *errptr must have been malloc()-ed by this library.)
  On success, a hyperleveldb routine leaves *errptr unchanged.
  On failure, hyperleveldb frees the old value of *errptr and
  set *errptr to a malloc()ed error message.

  (4) Bools have the type unsigned char (0 == false; rest == true)

  (5) All of the pointer arguments must be non-NULL.
*/

#ifndef STORAGE_LEVELDB_INCLUDE_C_H_
#define STORAGE_LEVELDB_INCLUDE_C_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

/* Exported types */

typedef struct hyperleveldb_t               hyperleveldb_t;
typedef struct hyperleveldb_cache_t         hyperleveldb_cache_t;
typedef struct hyperleveldb_comparator_t    hyperleveldb_comparator_t;
typedef struct hyperleveldb_env_t           hyperleveldb_env_t;
typedef struct hyperleveldb_filelock_t      hyperleveldb_filelock_t;
typedef struct hyperleveldb_filterpolicy_t  hyperleveldb_filterpolicy_t;
typedef struct hyperleveldb_iterator_t      hyperleveldb_iterator_t;
typedef struct hyperleveldb_logger_t        hyperleveldb_logger_t;
typedef struct hyperleveldb_options_t       hyperleveldb_options_t;
typedef struct hyperleveldb_randomfile_t    hyperleveldb_randomfile_t;
typedef struct hyperleveldb_readoptions_t   hyperleveldb_readoptions_t;
typedef struct hyperleveldb_seqfile_t       hyperleveldb_seqfile_t;
typedef struct hyperleveldb_snapshot_t      hyperleveldb_snapshot_t;
typedef struct hyperleveldb_writablefile_t  hyperleveldb_writablefile_t;
typedef struct hyperleveldb_writebatch_t    hyperleveldb_writebatch_t;
typedef struct hyperleveldb_writeoptions_t  hyperleveldb_writeoptions_t;

/* DB operations */

extern hyperleveldb_t* hyperleveldb_open(
    const hyperleveldb_options_t* options,
    const char* name,
    char** errptr);

extern void hyperleveldb_close(hyperleveldb_t* db);

extern void hyperleveldb_put(
    hyperleveldb_t* db,
    const hyperleveldb_writeoptions_t* options,
    const char* key, size_t keylen,
    const char* val, size_t vallen,
    char** errptr);

extern void hyperleveldb_delete(
    hyperleveldb_t* db,
    const hyperleveldb_writeoptions_t* options,
    const char* key, size_t keylen,
    char** errptr);

extern void hyperleveldb_write(
    hyperleveldb_t* db,
    const hyperleveldb_writeoptions_t* options,
    hyperleveldb_writebatch_t* batch,
    char** errptr);

/* Returns NULL if not found.  A malloc()ed array otherwise.
   Stores the length of the array in *vallen. */
extern char* hyperleveldb_get(
    hyperleveldb_t* db,
    const hyperleveldb_readoptions_t* options,
    const char* key, size_t keylen,
    size_t* vallen,
    char** errptr);

extern hyperleveldb_iterator_t* hyperleveldb_create_iterator(
    hyperleveldb_t* db,
    const hyperleveldb_readoptions_t* options);

extern const hyperleveldb_snapshot_t* hyperleveldb_create_snapshot(
    hyperleveldb_t* db);

extern void hyperleveldb_release_snapshot(
    hyperleveldb_t* db,
    const hyperleveldb_snapshot_t* snapshot);

/* Returns NULL if property name is unknown.
   Else returns a pointer to a malloc()-ed null-terminated value. */
extern char* hyperleveldb_property_value(
    hyperleveldb_t* db,
    const char* propname);

extern void hyperleveldb_approximate_sizes(
    hyperleveldb_t* db,
    int num_ranges,
    const char* const* range_start_key, const size_t* range_start_key_len,
    const char* const* range_limit_key, const size_t* range_limit_key_len,
    uint64_t* sizes);

extern void hyperleveldb_compact_range(
    hyperleveldb_t* db,
    const char* start_key, size_t start_key_len,
    const char* limit_key, size_t limit_key_len);

/* Management operations */

extern void hyperleveldb_destroy_db(
    const hyperleveldb_options_t* options,
    const char* name,
    char** errptr);

extern void hyperleveldb_repair_db(
    const hyperleveldb_options_t* options,
    const char* name,
    char** errptr);

/* Iterator */

extern void hyperleveldb_iter_destroy(hyperleveldb_iterator_t*);
extern unsigned char hyperleveldb_iter_valid(const hyperleveldb_iterator_t*);
extern void hyperleveldb_iter_seek_to_first(hyperleveldb_iterator_t*);
extern void hyperleveldb_iter_seek_to_last(hyperleveldb_iterator_t*);
extern void hyperleveldb_iter_seek(hyperleveldb_iterator_t*, const char* k, size_t klen);
extern void hyperleveldb_iter_next(hyperleveldb_iterator_t*);
extern void hyperleveldb_iter_prev(hyperleveldb_iterator_t*);
extern const char* hyperleveldb_iter_key(const hyperleveldb_iterator_t*, size_t* klen);
extern const char* hyperleveldb_iter_value(const hyperleveldb_iterator_t*, size_t* vlen);
extern void hyperleveldb_iter_get_error(const hyperleveldb_iterator_t*, char** errptr);

/* Write batch */

extern hyperleveldb_writebatch_t* hyperleveldb_writebatch_create();
extern void hyperleveldb_writebatch_destroy(hyperleveldb_writebatch_t*);
extern void hyperleveldb_writebatch_clear(hyperleveldb_writebatch_t*);
extern void hyperleveldb_writebatch_put(
    hyperleveldb_writebatch_t*,
    const char* key, size_t klen,
    const char* val, size_t vlen);
extern void hyperleveldb_writebatch_delete(
    hyperleveldb_writebatch_t*,
    const char* key, size_t klen);
extern void hyperleveldb_writebatch_iterate(
    hyperleveldb_writebatch_t*,
    void* state,
    void (*put)(void*, const char* k, size_t klen, const char* v, size_t vlen),
    void (*deleted)(void*, const char* k, size_t klen));

/* Options */

extern hyperleveldb_options_t* hyperleveldb_options_create();
extern void hyperleveldb_options_destroy(hyperleveldb_options_t*);
extern void hyperleveldb_options_set_comparator(
    hyperleveldb_options_t*,
    hyperleveldb_comparator_t*);
extern void hyperleveldb_options_set_filter_policy(
    hyperleveldb_options_t*,
    hyperleveldb_filterpolicy_t*);
extern void hyperleveldb_options_set_create_if_missing(
    hyperleveldb_options_t*, unsigned char);
extern void hyperleveldb_options_set_error_if_exists(
    hyperleveldb_options_t*, unsigned char);
extern void hyperleveldb_options_set_paranoid_checks(
    hyperleveldb_options_t*, unsigned char);
extern void hyperleveldb_options_set_env(hyperleveldb_options_t*, hyperleveldb_env_t*);
extern void hyperleveldb_options_set_info_log(hyperleveldb_options_t*, hyperleveldb_logger_t*);
extern void hyperleveldb_options_set_write_buffer_size(hyperleveldb_options_t*, size_t);
extern void hyperleveldb_options_set_max_open_files(hyperleveldb_options_t*, int);
extern void hyperleveldb_options_set_cache(hyperleveldb_options_t*, hyperleveldb_cache_t*);
extern void hyperleveldb_options_set_block_size(hyperleveldb_options_t*, size_t);
extern void hyperleveldb_options_set_block_restart_interval(hyperleveldb_options_t*, int);

enum {
  hyperleveldb_no_compression = 0,
  hyperleveldb_snappy_compression = 1
};
extern void hyperleveldb_options_set_compression(hyperleveldb_options_t*, int);

/* Comparator */

extern hyperleveldb_comparator_t* hyperleveldb_comparator_create(
    void* state,
    void (*destructor)(void*),
    int (*compare)(
        void*,
        const char* a, size_t alen,
        const char* b, size_t blen),
    const char* (*name)(void*));
extern void hyperleveldb_comparator_destroy(hyperleveldb_comparator_t*);

/* Filter policy */

extern hyperleveldb_filterpolicy_t* hyperleveldb_filterpolicy_create(
    void* state,
    void (*destructor)(void*),
    char* (*create_filter)(
        void*,
        const char* const* key_array, const size_t* key_length_array,
        int num_keys,
        size_t* filter_length),
    unsigned char (*key_may_match)(
        void*,
        const char* key, size_t length,
        const char* filter, size_t filter_length),
    const char* (*name)(void*));
extern void hyperleveldb_filterpolicy_destroy(hyperleveldb_filterpolicy_t*);

extern hyperleveldb_filterpolicy_t* hyperleveldb_filterpolicy_create_bloom(
    int bits_per_key);

/* Read options */

extern hyperleveldb_readoptions_t* hyperleveldb_readoptions_create();
extern void hyperleveldb_readoptions_destroy(hyperleveldb_readoptions_t*);
extern void hyperleveldb_readoptions_set_verify_checksums(
    hyperleveldb_readoptions_t*,
    unsigned char);
extern void hyperleveldb_readoptions_set_fill_cache(
    hyperleveldb_readoptions_t*, unsigned char);
extern void hyperleveldb_readoptions_set_snapshot(
    hyperleveldb_readoptions_t*,
    const hyperleveldb_snapshot_t*);

/* Write options */

extern hyperleveldb_writeoptions_t* hyperleveldb_writeoptions_create();
extern void hyperleveldb_writeoptions_destroy(hyperleveldb_writeoptions_t*);
extern void hyperleveldb_writeoptions_set_sync(
    hyperleveldb_writeoptions_t*, unsigned char);

/* Cache */

extern hyperleveldb_cache_t* hyperleveldb_cache_create_lru(size_t capacity);
extern void hyperleveldb_cache_destroy(hyperleveldb_cache_t* cache);

/* Env */

extern hyperleveldb_env_t* hyperleveldb_create_default_env();
extern void hyperleveldb_env_destroy(hyperleveldb_env_t*);

/* Utility */

/* Calls free(ptr).
   REQUIRES: ptr was malloc()-ed and returned by one of the routines
   in this file.  Note that in certain cases (typically on Windows), you
   may need to call this routine instead of free(ptr) to dispose of
   malloc()-ed memory returned by this library. */
extern void hyperleveldb_free(void* ptr);

/* Return the major version number for this release. */
extern int hyperleveldb_major_version();

/* Return the minor version number for this release. */
extern int hyperleveldb_minor_version();

#ifdef __cplusplus
}  /* end extern "C" */
#endif

#endif  /* STORAGE_LEVELDB_INCLUDE_C_H_ */
