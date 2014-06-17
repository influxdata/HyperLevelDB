// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "hyperleveldb/c.h"

#include <stdlib.h>
#include <unistd.h>
#include "hyperleveldb/cache.h"
#include "hyperleveldb/comparator.h"
#include "hyperleveldb/db.h"
#include "hyperleveldb/env.h"
#include "hyperleveldb/filter_policy.h"
#include "hyperleveldb/iterator.h"
#include "hyperleveldb/options.h"
#include "hyperleveldb/status.h"
#include "hyperleveldb/write_batch.h"

using hyperleveldb::Cache;
using hyperleveldb::Comparator;
using hyperleveldb::CompressionType;
using hyperleveldb::DB;
using hyperleveldb::Env;
using hyperleveldb::FileLock;
using hyperleveldb::FilterPolicy;
using hyperleveldb::Iterator;
using hyperleveldb::kMajorVersion;
using hyperleveldb::kMinorVersion;
using hyperleveldb::Logger;
using hyperleveldb::NewBloomFilterPolicy;
using hyperleveldb::NewLRUCache;
using hyperleveldb::Options;
using hyperleveldb::RandomAccessFile;
using hyperleveldb::Range;
using hyperleveldb::ReadOptions;
using hyperleveldb::SequentialFile;
using hyperleveldb::Slice;
using hyperleveldb::Snapshot;
using hyperleveldb::Status;
using hyperleveldb::WritableFile;
using hyperleveldb::WriteBatch;
using hyperleveldb::WriteOptions;

extern "C" {

struct hyperleveldb_t              { DB*               rep; };
struct hyperleveldb_iterator_t     { Iterator*         rep; };
struct hyperleveldb_writebatch_t   { WriteBatch        rep; };
struct hyperleveldb_snapshot_t     { const Snapshot*   rep; };
struct hyperleveldb_readoptions_t  { ReadOptions       rep; };
struct hyperleveldb_writeoptions_t { WriteOptions      rep; };
struct hyperleveldb_options_t      { Options           rep; };
struct hyperleveldb_cache_t        { Cache*            rep; };
struct hyperleveldb_seqfile_t      { SequentialFile*   rep; };
struct hyperleveldb_randomfile_t   { RandomAccessFile* rep; };
struct hyperleveldb_writablefile_t { WritableFile*     rep; };
struct hyperleveldb_logger_t       { Logger*           rep; };
struct hyperleveldb_filelock_t     { FileLock*         rep; };

struct hyperleveldb_comparator_t : public Comparator {
  void* state_;
  void (*destructor_)(void*);
  int (*compare_)(
      void*,
      const char* a, size_t alen,
      const char* b, size_t blen);
  const char* (*name_)(void*);

  virtual ~hyperleveldb_comparator_t() {
    (*destructor_)(state_);
  }

  virtual int Compare(const Slice& a, const Slice& b) const {
    return (*compare_)(state_, a.data(), a.size(), b.data(), b.size());
  }

  virtual const char* Name() const {
    return (*name_)(state_);
  }

  // No-ops since the C binding does not support key shortening methods.
  virtual void FindShortestSeparator(std::string*, const Slice&) const { }
  virtual void FindShortSuccessor(std::string* key) const { }
};

struct hyperleveldb_filterpolicy_t : public FilterPolicy {
  void* state_;
  void (*destructor_)(void*);
  const char* (*name_)(void*);
  char* (*create_)(
      void*,
      const char* const* key_array, const size_t* key_length_array,
      int num_keys,
      size_t* filter_length);
  unsigned char (*key_match_)(
      void*,
      const char* key, size_t length,
      const char* filter, size_t filter_length);

  virtual ~hyperleveldb_filterpolicy_t() {
    (*destructor_)(state_);
  }

  virtual const char* Name() const {
    return (*name_)(state_);
  }

  virtual void CreateFilter(const Slice* keys, int n, std::string* dst) const {
    std::vector<const char*> key_pointers(n);
    std::vector<size_t> key_sizes(n);
    for (int i = 0; i < n; i++) {
      key_pointers[i] = keys[i].data();
      key_sizes[i] = keys[i].size();
    }
    size_t len;
    char* filter = (*create_)(state_, &key_pointers[0], &key_sizes[0], n, &len);
    dst->append(filter, len);
    free(filter);
  }

  virtual bool KeyMayMatch(const Slice& key, const Slice& filter) const {
    return (*key_match_)(state_, key.data(), key.size(),
                         filter.data(), filter.size());
  }
};

struct hyperleveldb_env_t {
  Env* rep;
  bool is_default;
};

static bool SaveError(char** errptr, const Status& s) {
  assert(errptr != NULL);
  if (s.ok()) {
    return false;
  } else if (*errptr == NULL) {
    *errptr = strdup(s.ToString().c_str());
  } else {
    // TODO(sanjay): Merge with existing error?
    free(*errptr);
    *errptr = strdup(s.ToString().c_str());
  }
  return true;
}

static char* CopyString(const std::string& str) {
  char* result = reinterpret_cast<char*>(malloc(sizeof(char) * str.size()));
  memcpy(result, str.data(), sizeof(char) * str.size());
  return result;
}

hyperleveldb_t* hyperleveldb_open(
    const hyperleveldb_options_t* options,
    const char* name,
    char** errptr) {
  DB* db;
  if (SaveError(errptr, DB::Open(options->rep, std::string(name), &db))) {
    return NULL;
  }
  hyperleveldb_t* result = new hyperleveldb_t;
  result->rep = db;
  return result;
}

void hyperleveldb_close(hyperleveldb_t* db) {
  delete db->rep;
  delete db;
}

void hyperleveldb_put(
    hyperleveldb_t* db,
    const hyperleveldb_writeoptions_t* options,
    const char* key, size_t keylen,
    const char* val, size_t vallen,
    char** errptr) {
  SaveError(errptr,
            db->rep->Put(options->rep, Slice(key, keylen), Slice(val, vallen)));
}

void hyperleveldb_delete(
    hyperleveldb_t* db,
    const hyperleveldb_writeoptions_t* options,
    const char* key, size_t keylen,
    char** errptr) {
  SaveError(errptr, db->rep->Delete(options->rep, Slice(key, keylen)));
}


void hyperleveldb_write(
    hyperleveldb_t* db,
    const hyperleveldb_writeoptions_t* options,
    hyperleveldb_writebatch_t* batch,
    char** errptr) {
  SaveError(errptr, db->rep->Write(options->rep, &batch->rep));
}

char* hyperleveldb_get(
    hyperleveldb_t* db,
    const hyperleveldb_readoptions_t* options,
    const char* key, size_t keylen,
    size_t* vallen,
    char** errptr) {
  char* result = NULL;
  std::string tmp;
  Status s = db->rep->Get(options->rep, Slice(key, keylen), &tmp);
  if (s.ok()) {
    *vallen = tmp.size();
    result = CopyString(tmp);
  } else {
    *vallen = 0;
    if (!s.IsNotFound()) {
      SaveError(errptr, s);
    }
  }
  return result;
}

hyperleveldb_iterator_t* hyperleveldb_create_iterator(
    hyperleveldb_t* db,
    const hyperleveldb_readoptions_t* options) {
  hyperleveldb_iterator_t* result = new hyperleveldb_iterator_t;
  result->rep = db->rep->NewIterator(options->rep);
  return result;
}

const hyperleveldb_snapshot_t* hyperleveldb_create_snapshot(
    hyperleveldb_t* db) {
  hyperleveldb_snapshot_t* result = new hyperleveldb_snapshot_t;
  result->rep = db->rep->GetSnapshot();
  return result;
}

void hyperleveldb_release_snapshot(
    hyperleveldb_t* db,
    const hyperleveldb_snapshot_t* snapshot) {
  db->rep->ReleaseSnapshot(snapshot->rep);
  delete snapshot;
}

char* hyperleveldb_property_value(
    hyperleveldb_t* db,
    const char* propname) {
  std::string tmp;
  if (db->rep->GetProperty(Slice(propname), &tmp)) {
    // We use strdup() since we expect human readable output.
    return strdup(tmp.c_str());
  } else {
    return NULL;
  }
}

void hyperleveldb_approximate_sizes(
    hyperleveldb_t* db,
    int num_ranges,
    const char* const* range_start_key, const size_t* range_start_key_len,
    const char* const* range_limit_key, const size_t* range_limit_key_len,
    uint64_t* sizes) {
  Range* ranges = new Range[num_ranges];
  for (int i = 0; i < num_ranges; i++) {
    ranges[i].start = Slice(range_start_key[i], range_start_key_len[i]);
    ranges[i].limit = Slice(range_limit_key[i], range_limit_key_len[i]);
  }
  db->rep->GetApproximateSizes(ranges, num_ranges, sizes);
  delete[] ranges;
}

void hyperleveldb_compact_range(
    hyperleveldb_t* db,
    const char* start_key, size_t start_key_len,
    const char* limit_key, size_t limit_key_len) {
  Slice a, b;
  db->rep->CompactRange(
      // Pass NULL Slice if corresponding "const char*" is NULL
      (start_key ? (a = Slice(start_key, start_key_len), &a) : NULL),
      (limit_key ? (b = Slice(limit_key, limit_key_len), &b) : NULL));
}

void hyperleveldb_destroy_db(
    const hyperleveldb_options_t* options,
    const char* name,
    char** errptr) {
  SaveError(errptr, DestroyDB(name, options->rep));
}

void hyperleveldb_repair_db(
    const hyperleveldb_options_t* options,
    const char* name,
    char** errptr) {
  SaveError(errptr, RepairDB(name, options->rep));
}

void hyperleveldb_iter_destroy(hyperleveldb_iterator_t* iter) {
  delete iter->rep;
  delete iter;
}

unsigned char hyperleveldb_iter_valid(const hyperleveldb_iterator_t* iter) {
  return iter->rep->Valid();
}

void hyperleveldb_iter_seek_to_first(hyperleveldb_iterator_t* iter) {
  iter->rep->SeekToFirst();
}

void hyperleveldb_iter_seek_to_last(hyperleveldb_iterator_t* iter) {
  iter->rep->SeekToLast();
}

void hyperleveldb_iter_seek(hyperleveldb_iterator_t* iter, const char* k, size_t klen) {
  iter->rep->Seek(Slice(k, klen));
}

void hyperleveldb_iter_next(hyperleveldb_iterator_t* iter) {
  iter->rep->Next();
}

void hyperleveldb_iter_prev(hyperleveldb_iterator_t* iter) {
  iter->rep->Prev();
}

const char* hyperleveldb_iter_key(const hyperleveldb_iterator_t* iter, size_t* klen) {
  Slice s = iter->rep->key();
  *klen = s.size();
  return s.data();
}

const char* hyperleveldb_iter_value(const hyperleveldb_iterator_t* iter, size_t* vlen) {
  Slice s = iter->rep->value();
  *vlen = s.size();
  return s.data();
}

void hyperleveldb_iter_get_error(const hyperleveldb_iterator_t* iter, char** errptr) {
  SaveError(errptr, iter->rep->status());
}

hyperleveldb_writebatch_t* hyperleveldb_writebatch_create() {
  return new hyperleveldb_writebatch_t;
}

void hyperleveldb_writebatch_destroy(hyperleveldb_writebatch_t* b) {
  delete b;
}

void hyperleveldb_writebatch_clear(hyperleveldb_writebatch_t* b) {
  b->rep.Clear();
}

void hyperleveldb_writebatch_put(
    hyperleveldb_writebatch_t* b,
    const char* key, size_t klen,
    const char* val, size_t vlen) {
  b->rep.Put(Slice(key, klen), Slice(val, vlen));
}

void hyperleveldb_writebatch_delete(
    hyperleveldb_writebatch_t* b,
    const char* key, size_t klen) {
  b->rep.Delete(Slice(key, klen));
}

void hyperleveldb_writebatch_iterate(
    hyperleveldb_writebatch_t* b,
    void* state,
    void (*put)(void*, const char* k, size_t klen, const char* v, size_t vlen),
    void (*deleted)(void*, const char* k, size_t klen)) {
  class H : public WriteBatch::Handler {
   public:
    void* state_;
    void (*put_)(void*, const char* k, size_t klen, const char* v, size_t vlen);
    void (*deleted_)(void*, const char* k, size_t klen);
    virtual void Put(const Slice& key, const Slice& value) {
      (*put_)(state_, key.data(), key.size(), value.data(), value.size());
    }
    virtual void Delete(const Slice& key) {
      (*deleted_)(state_, key.data(), key.size());
    }
  };
  H handler;
  handler.state_ = state;
  handler.put_ = put;
  handler.deleted_ = deleted;
  b->rep.Iterate(&handler);
}

hyperleveldb_options_t* hyperleveldb_options_create() {
  return new hyperleveldb_options_t;
}

void hyperleveldb_options_destroy(hyperleveldb_options_t* options) {
  delete options;
}

void hyperleveldb_options_set_comparator(
    hyperleveldb_options_t* opt,
    hyperleveldb_comparator_t* cmp) {
  opt->rep.comparator = cmp;
}

void hyperleveldb_options_set_filter_policy(
    hyperleveldb_options_t* opt,
    hyperleveldb_filterpolicy_t* policy) {
  opt->rep.filter_policy = policy;
}

void hyperleveldb_options_set_create_if_missing(
    hyperleveldb_options_t* opt, unsigned char v) {
  opt->rep.create_if_missing = v;
}

void hyperleveldb_options_set_error_if_exists(
    hyperleveldb_options_t* opt, unsigned char v) {
  opt->rep.error_if_exists = v;
}

void hyperleveldb_options_set_paranoid_checks(
    hyperleveldb_options_t* opt, unsigned char v) {
  opt->rep.paranoid_checks = v;
}

void hyperleveldb_options_set_env(hyperleveldb_options_t* opt, hyperleveldb_env_t* env) {
  opt->rep.env = (env ? env->rep : NULL);
}

void hyperleveldb_options_set_info_log(hyperleveldb_options_t* opt, hyperleveldb_logger_t* l) {
  opt->rep.info_log = (l ? l->rep : NULL);
}

void hyperleveldb_options_set_write_buffer_size(hyperleveldb_options_t* opt, size_t s) {
  opt->rep.write_buffer_size = s;
}

void hyperleveldb_options_set_max_open_files(hyperleveldb_options_t* opt, int n) {
  opt->rep.max_open_files = n;
}

void hyperleveldb_options_set_cache(hyperleveldb_options_t* opt, hyperleveldb_cache_t* c) {
  opt->rep.block_cache = c->rep;
}

void hyperleveldb_options_set_block_size(hyperleveldb_options_t* opt, size_t s) {
  opt->rep.block_size = s;
}

void hyperleveldb_options_set_block_restart_interval(hyperleveldb_options_t* opt, int n) {
  opt->rep.block_restart_interval = n;
}

void hyperleveldb_options_set_compression(hyperleveldb_options_t* opt, int t) {
  opt->rep.compression = static_cast<CompressionType>(t);
}

hyperleveldb_comparator_t* hyperleveldb_comparator_create(
    void* state,
    void (*destructor)(void*),
    int (*compare)(
        void*,
        const char* a, size_t alen,
        const char* b, size_t blen),
    const char* (*name)(void*)) {
  hyperleveldb_comparator_t* result = new hyperleveldb_comparator_t;
  result->state_ = state;
  result->destructor_ = destructor;
  result->compare_ = compare;
  result->name_ = name;
  return result;
}

void hyperleveldb_comparator_destroy(hyperleveldb_comparator_t* cmp) {
  delete cmp;
}

hyperleveldb_filterpolicy_t* hyperleveldb_filterpolicy_create(
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
    const char* (*name)(void*)) {
  hyperleveldb_filterpolicy_t* result = new hyperleveldb_filterpolicy_t;
  result->state_ = state;
  result->destructor_ = destructor;
  result->create_ = create_filter;
  result->key_match_ = key_may_match;
  result->name_ = name;
  return result;
}

void hyperleveldb_filterpolicy_destroy(hyperleveldb_filterpolicy_t* filter) {
  delete filter;
}

hyperleveldb_filterpolicy_t* hyperleveldb_filterpolicy_create_bloom(int bits_per_key) {
  // Make a hyperleveldb_filterpolicy_t, but override all of its methods so
  // they delegate to a NewBloomFilterPolicy() instead of user
  // supplied C functions.
  struct Wrapper : public hyperleveldb_filterpolicy_t {
    const FilterPolicy* rep_;
    ~Wrapper() { delete rep_; }
    const char* Name() const { return rep_->Name(); }
    void CreateFilter(const Slice* keys, int n, std::string* dst) const {
      return rep_->CreateFilter(keys, n, dst);
    }
    bool KeyMayMatch(const Slice& key, const Slice& filter) const {
      return rep_->KeyMayMatch(key, filter);
    }
    static void DoNothing(void*) { }
  };
  Wrapper* wrapper = new Wrapper;
  wrapper->rep_ = NewBloomFilterPolicy(bits_per_key);
  wrapper->state_ = NULL;
  wrapper->destructor_ = &Wrapper::DoNothing;
  return wrapper;
}

hyperleveldb_readoptions_t* hyperleveldb_readoptions_create() {
  return new hyperleveldb_readoptions_t;
}

void hyperleveldb_readoptions_destroy(hyperleveldb_readoptions_t* opt) {
  delete opt;
}

void hyperleveldb_readoptions_set_verify_checksums(
    hyperleveldb_readoptions_t* opt,
    unsigned char v) {
  opt->rep.verify_checksums = v;
}

void hyperleveldb_readoptions_set_fill_cache(
    hyperleveldb_readoptions_t* opt, unsigned char v) {
  opt->rep.fill_cache = v;
}

void hyperleveldb_readoptions_set_snapshot(
    hyperleveldb_readoptions_t* opt,
    const hyperleveldb_snapshot_t* snap) {
  opt->rep.snapshot = (snap ? snap->rep : NULL);
}

hyperleveldb_writeoptions_t* hyperleveldb_writeoptions_create() {
  return new hyperleveldb_writeoptions_t;
}

void hyperleveldb_writeoptions_destroy(hyperleveldb_writeoptions_t* opt) {
  delete opt;
}

void hyperleveldb_writeoptions_set_sync(
    hyperleveldb_writeoptions_t* opt, unsigned char v) {
  opt->rep.sync = v;
}

hyperleveldb_cache_t* hyperleveldb_cache_create_lru(size_t capacity) {
  hyperleveldb_cache_t* c = new hyperleveldb_cache_t;
  c->rep = NewLRUCache(capacity);
  return c;
}

void hyperleveldb_cache_destroy(hyperleveldb_cache_t* cache) {
  delete cache->rep;
  delete cache;
}

hyperleveldb_env_t* hyperleveldb_create_default_env() {
  hyperleveldb_env_t* result = new hyperleveldb_env_t;
  result->rep = Env::Default();
  result->is_default = true;
  return result;
}

void hyperleveldb_env_destroy(hyperleveldb_env_t* env) {
  if (!env->is_default) delete env->rep;
  delete env;
}

void hyperleveldb_free(void* ptr) {
  free(ptr);
}

int hyperleveldb_major_version() {
  return kMajorVersion;
}

int hyperleveldb_minor_version() {
  return kMinorVersion;
}

}  // end extern "C"
