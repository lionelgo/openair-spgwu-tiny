/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file pfcp_switch.cpp
  \brief
  \author Lionel Gauthier
  \date 2019
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "pfcp_switch.hpp"
#include "spgwu_config.hpp"
#include "spgwu_pfcp_association.hpp"
#include "spgwu_s1u.hpp"

#include <algorithm>
#include <fstream>      // std::ifstream
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdexcept>
#include <net/ethernet.h>

using namespace pfcp;
using namespace gtpv1u;
using namespace spgwu;
using namespace std;

extern itti_mw *itti_inst;
extern spgwu_config spgwu_cfg;
extern spgwu_s1u  *spgwu_s1u_inst;



/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
          strrchr((file_name), '/') + 1 : (file_name))

struct l3fwd_pktio_s {
  odp_pktio_t pktio;
  odph_ethaddr_t mac_addr;
  odp_pktin_queue_t ifin[MAX_NB_QUEUE];
  odp_pktout_queue_t ifout[MAX_NB_QUEUE];
  int nb_rxq; /* capa max */
  int nb_txq; /* capa max */
  int rxq_idx;  /* requested, maybe greater than nb_rxq */
  int txq_idx;  /* requested, maybe greater than nb_txq */
};

struct l3fwd_qconf_s {
  uint8_t if_idx;   /* port index */
  uint8_t rxq_idx;  /* recv queue index in a port */
  uint8_t core_idx; /* this core should handle traffic */
};

struct thread_arg_s {
  uint64_t packets;
  uint64_t rx_drops;
  uint64_t tx_drops;
  struct {
    int if_idx; /* interface index */
    int nb_rxq; /* number of rxq this thread will access */
    int rxq[MAX_NB_QUEUE];  /* rxq[i] is index in pktio.ifin[] */
    int txq_idx;  /* index in pktio.ifout[] */
  } pktio[MAX_NB_PKTIO];
  int nb_pktio;
  int thr_idx;
};

typedef struct {
  char *if_names_buf;           /* memory buffer for all if_names */
  char *if_names[MAX_NB_PKTIO]; /* pointers to name strings stored in if_names_buf */
  int if_count;
  char *route_str[MAX_NB_ROUTE];
  unsigned int worker_count;
  struct l3fwd_qconf_s qconf_config[MAX_NB_QCONFS];
  unsigned int qconf_count;
  uint8_t hash_mode; /* 1:hash, 0:lpm */
  uint8_t dest_mac_changed[MAX_NB_PKTIO]; /* 1: dest mac from cmdline */
  int error_check; /* Check packets for errors */
} app_args_t;

typedef struct {
  app_args_t    cmd_args;
  struct l3fwd_pktio_s  l3fwd_pktios[MAX_NB_PKTIO];
  odph_odpthread_t  l3fwd_workers[MAX_NB_WORKER];
  struct thread_arg_s worker_args[MAX_NB_WORKER];
  odph_ethaddr_t    eth_dest_mac[MAX_NB_PKTIO];
  /** Global barrier to synchronize main and workers */
  odp_barrier_t barrier;
  /** Shm for storing global data */
  odp_shm_t shm;
  /** Break workers loop if set to 1 */
  odp_atomic_u32_t exit_threads;

  /* forward func, hash or lpm */
  int (*fwd_func)(odp_packet_t pkt, int sif);
} global_data_t;

static global_data_t *global;

/** Jenkins hash support.
  *
  * Copyright (C) 2006 Bob Jenkins (bob_jenkins@burtleburtle.net)
  *
  * http://burtleburtle.net/bob/hash/
  *
  * These are the credits from Bob's sources:
  *
  * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
  *
  * These are functions for producing 32-bit hashes for hash table lookup.
  * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
  * are externally useful functions.  Routines to test the hash are included
  * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
  * the public domain.  It has no warranty.
  *
  * $FreeBSD$
  */
#define JHASH_GOLDEN_RATIO  0x9e3779b9
#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))
#define FWD_BJ3_MIX(a, b, c) \
{ \
  a -= c; a ^= rot(c, 4); c += b; \
  b -= a; b ^= rot(a, 6); a += c; \
  c -= b; c ^= rot(b, 8); b += a; \
  a -= c; a ^= rot(c, 16); c += b; \
  b -= a; b ^= rot(a, 19); a += c; \
  c -= b; c ^= rot(b, 4); b += a; \
}

/**
 * Compute hash value from a flow
 */
static inline
uint64_t l3fwd_calc_hash(ipv4_tuple5_t *key)
{
  uint64_t l4_ports = 0;
  uint32_t dst_ip, src_ip;

  src_ip = key->src_ip;
  dst_ip = key->dst_ip + JHASH_GOLDEN_RATIO;
  FWD_BJ3_MIX(src_ip, dst_ip, l4_ports);

  return l4_ports;
}

/**
 * Parse text string representing an IPv4 address or subnet
 *
 * String is of the format "XXX.XXX.XXX.XXX(/W)" where
 * "XXX" is decimal value and "/W" is optional subnet length
 *
 * @param ipaddress  Pointer to IP address/subnet string to convert
 * @param addr       Pointer to return IPv4 address, host endianness
 * @param depth      Pointer to subnet bit width
 * @return 0 if successful else -1
 */
static inline
int parse_ipv4_string(char *ipaddress, uint32_t *addr, uint32_t *depth)
{
  int b[4];
  int qualifier = 32;
  int converted;
  uint32_t addr_le;

  if (strchr(ipaddress, '/')) {
    converted = sscanf(ipaddress, "%d.%d.%d.%d/%d",
           &b[3], &b[2], &b[1], &b[0],
           &qualifier);
    if (5 != converted)
      return -1;
  } else {
    converted = sscanf(ipaddress, "%d.%d.%d.%d",
           &b[3], &b[2], &b[1], &b[0]);
    if (4 != converted)
      return -1;
  }

  if ((b[0] > 255) || (b[1] > 255) || (b[2] > 255) || (b[3] > 255))
    return -1;
  if (!qualifier || (qualifier > 32))
    return -1;

  addr_le = b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
  *addr = odp_le_to_cpu_32(addr_le);
  *depth = qualifier;

  return 0;
}

/**
 * Generate text string representing IPv4 range/subnet, output
 * in "XXX.XXX.XXX.XXX/W" format
 *
 * @param b     Pointer to buffer to store string
 * @param range Pointer to IPv4 address range
 *
 * @return Pointer to supplied buffer
 */
static inline
char *ipv4_subnet_str(char *b, ip_addr_range_t *range)
{
  sprintf(b, "%d.%d.%d.%d/%d",
    0xFF & ((range->addr) >> 24),
    0xFF & ((range->addr) >> 16),
    0xFF & ((range->addr) >>  8),
    0xFF & ((range->addr) >>  0),
    range->depth);
  return b;
}

/**
 * Generate text string representing MAC address
 *
 * @param b     Pointer to buffer to store string
 * @param mac   Pointer to MAC address
 *
 * @return Pointer to supplied buffer
 */
static inline
char *mac_addr_str(char *b, odph_ethaddr_t *mac)
{
  uint8_t *byte;

  byte = mac->addr;
  sprintf(b, "%02X:%02X:%02X:%02X:%02X:%02X",
    byte[0], byte[1], byte[2], byte[3], byte[4], byte[5]);
  return b;
}

/**
 * Flow cache table entry
 */
typedef struct flow_entry_s {
  ipv4_tuple5_t key;    /**< match key */
  struct flow_entry_s *next;  /**< next entry in the bucket */
  fwd_db_entry_t *fwd_entry;  /**< entry info in db */
} flow_entry_t;

/**
 * Flow cache table bucket
 */
typedef struct flow_bucket_s {
  odp_rwlock_t  lock; /**< Bucket lock*/
  flow_entry_t  *next;  /**< First flow entry in bucket*/
} flow_bucket_t;

/**
 * Flow hash table, fast lookup cache
 */
typedef struct flow_table_s {
  odp_rwlock_t flow_lock; /**< flow table lock*/
  flow_entry_t *flows;  /**< flow store */
  flow_bucket_t *bucket;  /**< bucket store */
  uint32_t bkt_cnt;
  uint32_t flow_cnt;
  uint32_t next_flow; /**< next available flow in the store */
} flow_table_t;

static flow_table_t fwd_lookup_cache;

static void create_fwd_hash_cache(void)
{
  odp_shm_t   hash_shm;
  flow_bucket_t   *bucket = NULL;
  flow_entry_t    *flows;
  uint32_t    bucket_count, flow_count, size;
  uint32_t    i;

  flow_count = FWD_MAX_FLOW_COUNT;
  bucket_count = flow_count / FWD_DEF_BUCKET_ENTRIES;

  /*Reserve memory for Routing hash table*/
  size = sizeof(flow_bucket_t) * bucket_count +
    sizeof(flow_entry_t) * flow_count;
  hash_shm = odp_shm_reserve("flow_table", size, ODP_CACHE_LINE_SIZE, 0);
  if (hash_shm != ODP_SHM_INVALID)
    bucket = (flow_bucket_t*)odp_shm_addr(hash_shm);

  if (!bucket) {
    /* Try the second time with small request */
    flow_count /= 4;
    bucket_count = flow_count / FWD_DEF_BUCKET_ENTRIES;
    size = sizeof(flow_bucket_t) * bucket_count +
      sizeof(flow_entry_t) * flow_count;
    hash_shm = odp_shm_reserve("flow_table", size,
             ODP_CACHE_LINE_SIZE, 0);
    if (hash_shm == ODP_SHM_INVALID) {
      ODPH_ERR("Error: shared mem reserve failed.\n");
      exit(EXIT_FAILURE);
    }

    bucket = (flow_bucket_t*)odp_shm_addr(hash_shm);
    if (!bucket) {
      ODPH_ERR("Error: shared mem alloc failed.\n");
      exit(-1);
    }
  }

  size = sizeof(flow_bucket_t) * bucket_count;
  flows = (flow_entry_t *)(void *)((char *)bucket + size);

  fwd_lookup_cache.bucket = bucket;
  fwd_lookup_cache.bkt_cnt = bucket_count;
  fwd_lookup_cache.flows = flows;
  fwd_lookup_cache.flow_cnt = flow_count;

  /*Initialize bucket locks*/
  for (i = 0; i < bucket_count; i++) {
    bucket = &fwd_lookup_cache.bucket[i];
    odp_rwlock_init(&bucket->lock);
    bucket->next = NULL;
  }

  memset(flows, 0, sizeof(flow_entry_t) * flow_count);
  odp_rwlock_init(&fwd_lookup_cache.flow_lock);
  fwd_lookup_cache.next_flow = 0;
}

static inline flow_entry_t *get_new_flow(void)
{
  uint32_t next;
  flow_entry_t *flow = NULL;

  odp_rwlock_write_lock(&fwd_lookup_cache.flow_lock);
  next = fwd_lookup_cache.next_flow;
  if (next < fwd_lookup_cache.flow_cnt) {
    flow = &fwd_lookup_cache.flows[next];
    fwd_lookup_cache.next_flow++;
  }
  odp_rwlock_write_unlock(&fwd_lookup_cache.flow_lock);

  return flow;
}

static inline
int match_key_flow(ipv4_tuple5_t *key, flow_entry_t *flow)
{
  if (key->hi64 == flow->key.hi64 && key->lo64 == flow->key.lo64)
    return 1;

  return 0;
}

static inline
flow_entry_t *lookup_fwd_cache(ipv4_tuple5_t *key, flow_bucket_t *bucket)
{
  flow_entry_t *rst;

  odp_rwlock_read_lock(&bucket->lock);
  for (rst = bucket->next; rst != NULL; rst = rst->next) {
    if (match_key_flow(key, rst))
      break;
  }
  odp_rwlock_read_unlock(&bucket->lock);

  return rst;
}

static inline
flow_entry_t *insert_fwd_cache(ipv4_tuple5_t *key,
             flow_bucket_t *bucket,
             fwd_db_entry_t *entry)
{
  flow_entry_t *flow;

  if (!entry)
    return NULL;

  flow = get_new_flow();
  if (!flow)
    return NULL;

  flow->key = *key;
  flow->fwd_entry = entry;

  odp_rwlock_write_lock(&bucket->lock);
  if (bucket->next)
    flow->next = bucket->next;
  bucket->next = flow;
  odp_rwlock_write_unlock(&bucket->lock);

  return flow;
}

void init_fwd_hash_cache(void)
{
  fwd_db_entry_t *entry;
  flow_entry_t *flow;
  flow_bucket_t *bucket;
  uint64_t hash;
  uint32_t i, nb_hosts;
  ipv4_tuple5_t key;

  create_fwd_hash_cache();

  /**
   * warm up the lookup cache with possible hosts.
   * with millions flows, save significant time during runtime.
   */
  memset(&key, 0, sizeof(key));
  for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
    nb_hosts = 1 << (32 - entry->subnet.depth);
    for (i = 0; i < nb_hosts; i++) {
      key.dst_ip = entry->subnet.addr + i;
      hash = l3fwd_calc_hash(&key);
      hash &= fwd_lookup_cache.bkt_cnt - 1;
      bucket = &fwd_lookup_cache.bucket[hash];
      flow = lookup_fwd_cache(&key, bucket);
      if (flow)
        return;

      flow = insert_fwd_cache(&key, bucket, entry);
      if (!flow)
        goto out;
    }
  }
out:
  return;
}

/** Global pointer to fwd db */
fwd_db_t *fwd_db;

void init_fwd_db(void)
{
  odp_shm_t shm;

  shm = odp_shm_reserve("shm_fwd_db",
            sizeof(fwd_db_t),
            ODP_CACHE_LINE_SIZE,
            0);

  if (shm == ODP_SHM_INVALID) {
    ODPH_ERR("Error: shared mem reserve failed.\n");
    exit(EXIT_FAILURE);
  }

  fwd_db = (fwd_db_t*)odp_shm_addr(shm);

  if (fwd_db == NULL) {
    ODPH_ERR("Error: shared mem alloc failed.\n");
    exit(EXIT_FAILURE);
  }
  memset(fwd_db, 0, sizeof(*fwd_db));
}

int create_fwd_db_entry(char *input, char **oif, uint8_t **dst_mac)
{
  int pos = 0;
  char *local;
  char *str;
  char *save;
  char *token;
  fwd_db_entry_t *entry = &fwd_db->array[fwd_db->index];

  *oif = NULL;
  *dst_mac = NULL;

  /* Verify we haven't run out of space */
  if (MAX_DB <= fwd_db->index)
    return -1;

  /* Make a local copy */
  local = (char *)malloc(strlen(input) + 1);
  if (NULL == local)
    return -1;
  strcpy(local, input);

  /* Setup for using "strtok_r" to search input string */
  str = local;
  save = NULL;

  /* Parse tokens separated by ',' */
  while (NULL != (token = strtok_r(str, ",", &save))) {
    str = NULL;  /* reset str for subsequent strtok_r calls */

    /* Parse token based on its position */
    switch (pos) {
    case 0:
      parse_ipv4_string(token,
            &entry->subnet.addr,
            &entry->subnet.depth);
      break;
    case 1:
      strncpy(entry->oif, token, OIF_LEN - 1);
      entry->oif[OIF_LEN - 1] = 0;
      *oif = entry->oif;
      break;
    case 2:
      if (odph_eth_addr_parse(&entry->dst_mac, token) < 0) {
        free(local);
        return -1;
      }
      *dst_mac = entry->dst_mac.addr;
      break;

    default:
      printf("ERROR: extra token \"%s\" at position %d\n",
             token, pos);
      break;
    }

    /* Advance to next position */
    pos++;
  }

  /* Add route to the list */
  fwd_db->index++;
  entry->next = fwd_db->list;
  fwd_db->list = entry;

  free(local);
  return 0;
}

void resolve_fwd_db(char *intf, int portid, uint8_t *mac)
{
  fwd_db_entry_t *entry;

  /* Walk the list and attempt to set output and MAC */
  for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
    if (strcmp(intf, entry->oif))
      continue;

    entry->oif_id = portid;
    memcpy(entry->src_mac.addr, mac, ODPH_ETHADDR_LEN);
  }
}

void dump_fwd_db_entry(fwd_db_entry_t *entry)
{
  char subnet_str[MAX_STRING];
  char mac_str[MAX_STRING];

  mac_addr_str(mac_str, &entry->dst_mac);
  printf("%-32s%-32s%-16s\n",
         ipv4_subnet_str(subnet_str, &entry->subnet),
         entry->oif, mac_str);
}

void dump_fwd_db(void)
{
  fwd_db_entry_t *entry;

  printf("Routing table\n"
         "-----------------\n"
         "%-32s%-32s%-16s\n",
         "subnet", "next_hop", "dest_mac");

  for (entry = fwd_db->list; NULL != entry; entry = entry->next)
    dump_fwd_db_entry(entry);

  printf("\n");
}

fwd_db_entry_t *find_fwd_db_entry(ipv4_tuple5_t *key)
{
  fwd_db_entry_t *entry;
  flow_entry_t *flow;
  flow_bucket_t *bucket;
  uint64_t hash;
  ipv4_tuple5_t newkey;

  newkey.hi64 = 0;
  newkey.lo64 = 0;
  newkey.dst_ip = key->dst_ip;
  key = &newkey;

  /* first find in cache */
  hash = l3fwd_calc_hash(key);
  hash &= fwd_lookup_cache.bkt_cnt - 1;
  bucket = &fwd_lookup_cache.bucket[hash];
  flow = lookup_fwd_cache(key, bucket);
  if (flow)
    return flow->fwd_entry;

  for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
    uint32_t mask;

    mask = ((1u << entry->subnet.depth) - 1) <<
      (32 - entry->subnet.depth);

    if (entry->subnet.addr == (key->dst_ip & mask))
      break;
  }

  insert_fwd_cache(key, bucket, entry);

  return entry;
}

/**
 * This is a simple implementation of lpm based on patricia tree.
 *
 * Tradeoff exists between memory consumption and lookup time.
 * Currently it prefers 5 levels: {16, 4, 4, 4, 4}, could be 3
 * levels: {16, 8, 8} by defining FIB_NEXT_STRIDE as 8. Other
 * levels are also possible.
 *
 * the ip here is host endian, when doing init or lookup, the
 * caller should do endianness conversion if needed.
 */

#define FIB_IP_WIDTH 32
#define FIB_FIRST_STRIDE 16
#define FIB_NEXT_STRIDE 4
#define FIB_NEXT_SIZE (1 << FIB_NEXT_STRIDE)
#define FIB_SUB_COUNT 16384
#define DEPTH_TO_MASK(depth) ((1 << (depth)) - 1)

typedef struct fib_node_s {
  union {
    uint32_t next_hop;
    struct fib_node_s *next; /* next level table */
  };
  uint8_t valid :1; /* 1, this node has a valid next hop */
  uint8_t end :1; /* 0, next points to the extended table */
  uint8_t depth :6; /* bit length of subnet mask */
} fib_node_t;

typedef struct fib_sub_tbl_s {
  fib_node_t *fib_nodes;
  uint32_t fib_count;
  uint32_t fib_idx;
} fib_sub_tbl_t;

static fib_node_t fib_rt_tbl[1 << FIB_FIRST_STRIDE];
static fib_sub_tbl_t fib_lpm_cache;

static inline fib_node_t *fib_alloc_sub(void)
{
  fib_node_t *sub_tbl = NULL;
  uint32_t i, nb_entry;

  /* extend to next level */
  if (fib_lpm_cache.fib_idx < fib_lpm_cache.fib_count) {
    nb_entry = (fib_lpm_cache.fib_idx + 1) * FIB_NEXT_SIZE;
    sub_tbl = &fib_lpm_cache.fib_nodes[nb_entry];
    fib_lpm_cache.fib_idx++;
    for (i = 0; i < nb_entry; i++) {
      sub_tbl[i].valid = 0;
      sub_tbl[i].end = 1;
    }
  }

  return sub_tbl;
}

static void fib_update_node(fib_node_t *fe, int port, int depth)
{
  fib_node_t *p;
  int i;

  if (fe->end) {
    if (!fe->valid) {
      fe->depth = depth;
      fe->next_hop = port;
      fe->valid = 1;
    } else if (fe->depth <= depth) {
      fe->next_hop = port;
      fe->depth = depth;
    }

    return;
  }

  for (i = 0; i < FIB_NEXT_SIZE; i++) {
    p = &fe->next[i];
    if (p->end)
      fib_update_node(p, port, depth);
  }
}

static void fib_insert_node(fib_node_t *fe, uint32_t ip, uint32_t next_hop,
          int ip_width, int eat_bits, int depth)
{
  int i;
  uint32_t idx, port;
  fib_node_t *p;

  if (fe->end) {
    port = fe->next_hop;
    p = fib_alloc_sub();
    if (!p)
      return;

    fe->next = p;
    fe->end = 0;
    if (fe->valid) {
      for (i = 0; i < FIB_NEXT_SIZE; i++) {
        p = &fe->next[i];
        p->next_hop = port;
        p->depth = fe->depth;
      }
    }
  }
  if (depth - eat_bits <= FIB_NEXT_STRIDE) {
    ip_width -= depth - eat_bits;
    idx = ip >> ip_width;
    ip &= DEPTH_TO_MASK(ip_width);
    p = &fe->next[idx];
    fib_update_node(p, next_hop, depth);
  } else {
    ip_width -= FIB_NEXT_STRIDE;
    idx = ip >> ip_width;
    p = &fe->next[idx];
    ip &= DEPTH_TO_MASK(ip_width);
    eat_bits += FIB_NEXT_STRIDE;
    fib_insert_node(p, ip, next_hop, ip_width, eat_bits, depth);
  }
}

void fib_tbl_init(void)
{
  int i;
  fib_node_t *fe;
  uint32_t size;
  odp_shm_t lpm_shm;

  for (i = 0; i < (1 << FIB_FIRST_STRIDE); i++) {
    fe = &fib_rt_tbl[i];
    fe->valid = 0;
    fe->end = 1;
    fe->depth = 0;
    fe->next_hop = 0;
  }

  size = FIB_NEXT_SIZE * FIB_SUB_COUNT;
  /*Reserve memory for Routing hash table*/
  lpm_shm = odp_shm_reserve("fib_lpm_sub", size, ODP_CACHE_LINE_SIZE, 0);
  if (lpm_shm == ODP_SHM_INVALID) {
    ODPH_ERR("Error: shared mem reserve failed.\n");
    exit(EXIT_FAILURE);
  }

  fe = (fib_node_t*)odp_shm_addr(lpm_shm);
  if (!fe) {
    ODPH_ERR("Error: shared mem alloc failed for lpm cache.\n");
    exit(-1);
  }

  fib_lpm_cache.fib_nodes = fe;
  fib_lpm_cache.fib_count = FIB_SUB_COUNT;
  fib_lpm_cache.fib_idx = 0;
}

void fib_tbl_insert(uint32_t ip, int port, int depth)
{
  fib_node_t *fe, *p;
  uint32_t idx;
  int i, j;
  int nb_bits;

  nb_bits = FIB_FIRST_STRIDE;
  idx = ip >> (FIB_IP_WIDTH - nb_bits);
  fe = &fib_rt_tbl[idx];
  if (depth <= nb_bits) {
    if (fe->end) {
      fe->next_hop = port;
      fe->depth = depth;
      fe->valid = 1;
      return;
    }

    for (i = 0; i < FIB_NEXT_SIZE; i++) {
      p = &fe->next[i];
      if (p->end)
        fib_update_node(p, port, depth);
      else
        for (j = 0; j < FIB_NEXT_SIZE; j++)
          fib_update_node(&p->next[j], port,
              depth);
    }

    return;
  }

  /* need to check sub table */
  ip &= DEPTH_TO_MASK(FIB_IP_WIDTH - nb_bits);
  fib_insert_node(fe, ip, port, FIB_IP_WIDTH - nb_bits, nb_bits, depth);
}

int fib_tbl_lookup(uint32_t ip, int *port)
{
  fib_node_t *fe;
  uint32_t idx;
  int nb_bits;

  nb_bits = FIB_IP_WIDTH - FIB_FIRST_STRIDE;
  idx = ip >> nb_bits;
  fe = &fib_rt_tbl[idx];

  ip &= DEPTH_TO_MASK(nb_bits);
  while (!fe->end) {
    nb_bits -= FIB_NEXT_STRIDE;
    idx = ip >> nb_bits;
    fe = &fe->next[idx];
    ip &= DEPTH_TO_MASK(nb_bits);
  }
  *port = fe->next_hop;

  return fe->valid ? 0 : -1;
}

static int create_pktio(const char *name, odp_pool_t pool,
      struct l3fwd_pktio_s *fwd_pktio)
{
  odp_pktio_param_t pktio_param;
  odp_pktio_t pktio;
  odp_pktio_capability_t capa;
  odp_pktio_config_t config;
  int rc;

  odp_pktio_param_init(&pktio_param);

  pktio = odp_pktio_open(name, pool, &pktio_param);
  if (pktio == ODP_PKTIO_INVALID) {
    printf("Failed to open %s\n", name);
    return -1;
  }
  fwd_pktio->pktio = pktio;

  rc = odp_pktio_capability(pktio, &capa);
  if (rc) {
    printf("Error: pktio %s: unable to read capabilities!\n",
           name);

    return -1;
  }

  odp_pktio_config_init(&config);
  config.parser.layer = global->cmd_args.error_check ?
      ODP_PROTO_LAYER_ALL :
      ODP_PROTO_LAYER_L4;

  /* Provide hint to pktio that packet references are not used */
  config.pktout.bit.no_packet_refs = 1;

  odp_pktio_config(pktio, &config);

  fwd_pktio->nb_rxq = (int)capa.max_input_queues;
  fwd_pktio->nb_txq = (int)capa.max_output_queues;

  if (fwd_pktio->nb_rxq > MAX_NB_QUEUE)
    fwd_pktio->nb_rxq = MAX_NB_QUEUE;

  if (fwd_pktio->nb_txq > MAX_NB_QUEUE)
    fwd_pktio->nb_txq = MAX_NB_QUEUE;

  return 0;
}

static void setup_fwd_db(void)
{
  fwd_db_entry_t *entry;
  int if_idx;
  app_args_t *args;

  args = &global->cmd_args;
  if (args->hash_mode)
    init_fwd_hash_cache();
  else
    fib_tbl_init();

  for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
    if_idx = entry->oif_id;
    if (!args->hash_mode)
      fib_tbl_insert(entry->subnet.addr, if_idx,
               entry->subnet.depth);
    if (args->dest_mac_changed[if_idx])
      global->eth_dest_mac[if_idx] = entry->dst_mac;
    else
      entry->dst_mac = global->eth_dest_mac[if_idx];
  }
}

/**
 * Decrement TTL and incrementally update checksum
 *
 * @param ip  IPv4 header
 */
static inline void ipv4_dec_ttl_csum_update(odph_ipv4hdr_t *ip)
{
  uint16_t a = ~odp_cpu_to_be_16(1 << 8);

  ip->ttl--;
  if (ip->chksum >= a)
    ip->chksum -= a;
  else
    ip->chksum += odp_cpu_to_be_16(1 << 8);
}

static inline int l3fwd_pkt_hash(odp_packet_t pkt, int sif)
{
  fwd_db_entry_t *entry;
  ipv4_tuple5_t key;
  odph_ethhdr_t *eth;
  odph_udphdr_t  *udp;
  odph_ipv4hdr_t *ip;
  int dif;

  ip = (odph_ipv4hdr_t*)odp_packet_l3_ptr(pkt, NULL);
  key.dst_ip = odp_be_to_cpu_32(ip->dst_addr);
  key.src_ip = odp_be_to_cpu_32(ip->src_addr);
  key.proto = ip->proto;

  if (odp_packet_has_udp(pkt) ||
      odp_packet_has_tcp(pkt)) {
    /* UDP or TCP*/
    void *ptr = odp_packet_l4_ptr(pkt, NULL);

    udp = (odph_udphdr_t *)ptr;
    key.src_port = odp_be_to_cpu_16(udp->src_port);
    key.dst_port = odp_be_to_cpu_16(udp->dst_port);
  } else {
    key.src_port = 0;
    key.dst_port = 0;
  }
  entry = find_fwd_db_entry(&key);
  ipv4_dec_ttl_csum_update(ip);
  eth = (odph_ethhdr_t*)odp_packet_l2_ptr(pkt, NULL);
  if (entry) {
    eth->src = entry->src_mac;
    eth->dst = entry->dst_mac;
    dif = entry->oif_id;
  } else {
    /* no route, send by src port */
    eth->dst = eth->src;
    dif = sif;
  }

  return dif;
}

static inline int l3fwd_pkt_lpm(odp_packet_t pkt, int sif)
{
  odph_ipv4hdr_t *ip;
  odph_ethhdr_t *eth;
  int dif;
  int ret;

  ip = (odph_ipv4hdr_t*)odp_packet_l3_ptr(pkt, NULL);
  ipv4_dec_ttl_csum_update(ip);
  eth = (odph_ethhdr_t*)odp_packet_l2_ptr(pkt, NULL);

  /* network byte order maybe different from host */
  ret = fib_tbl_lookup(odp_be_to_cpu_32(ip->dst_addr), &dif);
  if (ret)
    dif = sif;

  eth->dst = global->eth_dest_mac[dif];
  eth->src = global->l3fwd_pktios[dif].mac_addr;

  return dif;
}

/**
 * Drop unsupported packets and packets containing errors.
 *
 * Frees packets with errors or unsupported protocol and modifies pkt_tbl[] to
 * only contain valid packets.
 *
 * @param pkt_tbl  Array of packets
 * @param num      Number of packets in pkt_tbl[]
 *
 * @return Number of packets dropped
 */
static inline int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned num)
{
  odp_packet_t pkt;
  unsigned dropped = 0;
  unsigned i, j;
  int err;

  for (i = 0, j = 0; i < num; ++i) {
    pkt = pkt_tbl[i];
    err = 0;

    if (global->cmd_args.error_check)
      err = odp_packet_has_error(pkt);

    if (odp_unlikely(err || !odp_packet_has_ipv4(pkt))) {
      odp_packet_free(pkt);
      dropped++;
    } else if (odp_unlikely(i != j++)) {
      pkt_tbl[j - 1] = pkt;
    }
  }

  return dropped;
}

static int run_worker(void *arg)
{
  int if_idx;
  struct thread_arg_s *thr_arg = (struct thread_arg_s *)arg;
  odp_pktin_queue_t inq;
  int input_ifs[thr_arg->nb_pktio];
  odp_pktin_queue_t input_queues[thr_arg->nb_pktio];
  odp_pktout_queue_t output_queues[global->cmd_args.if_count];
  odp_packet_t pkt_tbl[MAX_PKT_BURST];
  odp_packet_t *tbl;
  int pkts, drop, sent;
  int dst_port, dif;
  int i, j;
  int pktio = 0;
  int num_pktio = 0;

  /* Copy all required handles to local memory */
  for (i = 0; i < global->cmd_args.if_count; i++) {
    int txq_idx = thr_arg->pktio[i].txq_idx;

    output_queues[i] =  global->l3fwd_pktios[i].ifout[txq_idx];

    if_idx = thr_arg->pktio[i].if_idx;
    for (j = 0; j < thr_arg->pktio[i].nb_rxq; j++) {
      int rxq_idx = thr_arg->pktio[i].rxq[j];

      inq = global->l3fwd_pktios[if_idx].ifin[rxq_idx];
      input_ifs[num_pktio] = if_idx;
      input_queues[num_pktio] = inq;
      num_pktio++;
    }
  }

  if (num_pktio == 0)
    ODPH_ABORT("No pktio devices found\n");

  if_idx = input_ifs[pktio];
  inq = input_queues[pktio];

  odp_barrier_wait(&global->barrier);

  while (!odp_atomic_load_u32(&global->exit_threads)) {
    if (num_pktio > 1) {
      if_idx = input_ifs[pktio];
      inq = input_queues[pktio];
      pktio++;
      if (pktio == num_pktio)
        pktio = 0;
    }

    pkts = odp_pktin_recv(inq, pkt_tbl, MAX_PKT_BURST);
    if (pkts < 1)
      continue;

    thr_arg->packets += pkts;
    drop = drop_err_pkts(pkt_tbl, pkts);
    pkts -= drop;
    thr_arg->rx_drops += drop;
    if (odp_unlikely(pkts < 1))
      continue;

    dif = global->fwd_func(pkt_tbl[0], if_idx);
    tbl = &pkt_tbl[0];
    while (pkts) {
      dst_port = dif;
      for (i = 1; i < pkts; i++) {
        dif = global->fwd_func(tbl[i], if_idx);
        if (dif != dst_port)
          break;
      }
      sent = odp_pktout_send(output_queues[dst_port], tbl, i);
      if (odp_unlikely(sent < i)) {
        sent = sent < 0 ? 0 : sent;
        odp_packet_free_multi(&tbl[sent], i - sent);
        thr_arg->tx_drops += i - sent;
      }

      if (i < pkts)
        tbl += i;

      pkts -= i;
    }
  }

  /* Make sure that latest stat writes are visible to other threads */
  odp_mb_full();

  return 0;
}

static int find_port_id_by_name(char *name, app_args_t *args)
{
  int i;

  if (!name)
    return -1;

  for (i = 0; i < args->if_count; i++) {
    if (!strcmp(name, args->if_names[i]))
      return i;
  }

  return -1;
}

/* split string into tokens */
static int split_string(char *str, int stringlen,
      char **tokens, int maxtokens, char delim)
{
  int i, tok = 0;
  int tokstart = 1; /* first token is right at start of string */

  if (str == NULL || tokens == NULL)
    goto einval_error;

  for (i = 0; i < stringlen; i++) {
    if (str[i] == '\0' || tok >= maxtokens)
      break;
    if (tokstart) {
      tokstart = 0;
      tokens[tok++] = &str[i];
    }
    if (str[i] == delim) {
      str[i] = '\0';
      tokstart = 1;
    }
  }
  return tok;

einval_error:
  errno = EINVAL;
  return -1;
}

static int parse_config(char *cfg_str, app_args_t *args)
{
  char s[256];
  const char *p, *p0 = cfg_str;
  char *end;
  enum fieldnames {
    FLD_PORT = 0,
    FLD_QUEUE,
    FLD_LCORE,
    FLD_LAST
  };
  unsigned long int_fld[FLD_LAST];
  char *str_fld[FLD_LAST];
  int i;
  unsigned size;
  int nb_qconfs = 0;
  struct l3fwd_qconf_s *qconf_array = &args->qconf_config[0];

  p = strchr(p0, '(');
  while (p != NULL) {
    ++p;
    p0 = strchr(p, ')');
    if (p0 == NULL)
      return -1;

    size = p0 - p;
    if (size >= sizeof(s))
      return -1;

    snprintf(s, sizeof(s), "%.*s", size, p);
    i = split_string(s, sizeof(s), str_fld, FLD_LAST, ',');
    if (i != FLD_LAST)
      return -1;
    for (i = 0; i < FLD_LAST; i++) {
      errno = 0;
      int_fld[i] = strtoul(str_fld[i], &end, 0);
      if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
        return -1;
    }
    if (nb_qconfs >= MAX_NB_QCONFS) {
      printf("exceeded max number of queue params: %d\n",
             nb_qconfs);
      return -1;
    }
    qconf_array[nb_qconfs].if_idx = (uint8_t)int_fld[FLD_PORT];
    qconf_array[nb_qconfs].rxq_idx = (uint8_t)int_fld[FLD_QUEUE];
    qconf_array[nb_qconfs].core_idx = (uint8_t)int_fld[FLD_LCORE];
    ++nb_qconfs;

    p = strchr(p0, '(');
  }
  args->qconf_count = nb_qconfs;

  return 0;
}

static std::string string_to_hex(const char* input, const size_t len)
{
    static const char* const lut = "0123456789ABCDEF";

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}
//------------------------------------------------------------------------------
void pfcp_switch::stop_timer_min_commit_interval()
{
  if (timer_min_commit_interval_id) {
    itti_inst->timer_remove(timer_min_commit_interval_id);
  }
  timer_min_commit_interval_id = 0;
}
//------------------------------------------------------------------------------
void pfcp_switch::start_timer_min_commit_interval()
{
  stop_timer_min_commit_interval();
  timer_min_commit_interval_id = itti_inst->timer_setup (PFCP_SWITCH_MIN_COMMIT_INTERVAL_MILLISECONDS/1000, PFCP_SWITCH_MIN_COMMIT_INTERVAL_MILLISECONDS%1000, TASK_SPGWU_APP, TASK_SPGWU_PFCP_SWITCH_MIN_COMMIT_INTERVAL);
}
//------------------------------------------------------------------------------
void pfcp_switch::stop_timer_max_commit_interval()
{
  if (timer_max_commit_interval_id) {
    itti_inst->timer_remove(timer_max_commit_interval_id);
  }
  timer_max_commit_interval_id = 0;
}
//------------------------------------------------------------------------------
void pfcp_switch::start_timer_max_commit_interval()
{
  stop_timer_max_commit_interval();
  timer_max_commit_interval_id = itti_inst->timer_setup (PFCP_SWITCH_MAX_COMMIT_INTERVAL_MILLISECONDS/1000, PFCP_SWITCH_MAX_COMMIT_INTERVAL_MILLISECONDS%1000, TASK_SPGWU_APP, TASK_SPGWU_PFCP_SWITCH_MAX_COMMIT_INTERVAL);
}
//------------------------------------------------------------------------------
void pfcp_switch::time_out_min_commit_interval(const uint32_t timer_id)
{
  if (timer_id == timer_min_commit_interval_id) {
    stop_timer_max_commit_interval();
    timer_min_commit_interval_id = 0;
    commit_changes();
  }
}
//------------------------------------------------------------------------------
void pfcp_switch::time_out_max_commit_interval(const uint32_t timer_id)
{
  if (timer_id == timer_max_commit_interval_id) {
    stop_timer_min_commit_interval();
    timer_max_commit_interval_id = 0;
    commit_changes();
  }
}
//------------------------------------------------------------------------------
void pfcp_switch::commit_changes()
{
}

//------------------------------------------------------------------------------
void pfcp_switch::pdn_read_loop(const util::thread_sched_params& sched_params)
{
  int        bytes_received = 0;

  sched_params.apply(TASK_NONE, Logger::pfcp_switch());

  struct msghdr msg = {};
  msg.msg_iov = &msg_iov_;
  msg.msg_iovlen = 1;

  while (1) {
    if ((bytes_received = recvmsg(sock_r, &msg, 0)) > 0) {
      pfcp_session_look_up_pack_in_core((const char*)msg_iov_.iov_base, bytes_received);
    } else {
      Logger::pfcp_switch().error( "recvmsg failed rc=%d:%s", bytes_received, strerror (errno));
    }
  }
}
//------------------------------------------------------------------------------
void pfcp_switch::send_to_core(char* const ip_packet, const ssize_t len)
{
  ssize_t bytes_sent;
  //Logger::pfcp_switch().info( "pfcp_switch::send_to_core %d bytes ", len);
  struct sockaddr_in dst; // no clear
  dst.sin_addr.s_addr = ((struct iphdr*)ip_packet)->daddr;
  dst.sin_family = AF_INET;
  if((bytes_sent = sendto(sock_w, ip_packet, len, 0, (struct sockaddr *)&dst, sizeof(dst))) < 0) {
    Logger::pfcp_switch().error( "sendto failed rc=%d:%s", bytes_sent, strerror (errno));
  }
}
//------------------------------------------------------------------------------
int pfcp_switch::create_pdn_socket (const char * const ifname, const bool promisc, int& if_index)
{
  struct sockaddr_in                      addr = {};
  int                                     sd = 0;

//  const int len = strnlen (ifname, IFNAMSIZ);
//  if (len == IFNAMSIZ) {
//    Logger::pfcp_switch().error( "Interface name too long %s", ifname);
//    return RETURNerror;
//  }

  /*
   * Create socket
   * The  socket_type is either SOCK_RAW for raw packets including the link-level header or SOCK_DGRAM for cooked packets with the link-level header removed.
   */

  if ((sd = socket (AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))) < 0) {
    /*
     * Socket creation has failed...
     */
    Logger::pfcp_switch().error( "Socket creation failed (%s)", strerror (errno));
    return RETURNerror;
  }


  if (ifname) {
    struct ifreq ifr = {};
    strncpy ((char *) ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0) {
      Logger::pfcp_switch().error( "Get interface index failed (%s) for %s", strerror (errno), ifname);
      close (sd);
      return RETURNerror;
    }

    if_index = ifr.ifr_ifindex;

    struct sockaddr_ll sll = {};
    sll.sll_family = AF_PACKET;          /* Always AF_PACKET */
    sll.sll_protocol = htons(ETH_P_ALL); /* Physical-layer protocol */
    sll.sll_ifindex = ifr.ifr_ifindex;   /* Interface number */
    if (bind (sd, (struct sockaddr *)&sll, sizeof (sll)) < 0) {
      /*
       * Bind failed
       */
      Logger::pfcp_switch().error("Socket bind to %s failed (%s)", ifname, strerror (errno));
      close (sd);
      return RETURNerror;
    }

    if (promisc) {
      struct packet_mreq      mreq = {};
      mreq.mr_ifindex = if_index;
      mreq.mr_type = PACKET_MR_PROMISC;
      if (setsockopt (sd, SOL_PACKET,PACKET_ADD_MEMBERSHIP, &mreq, sizeof (mreq)) < 0) {
        Logger::pfcp_switch().error("Set promiscuous mode failed (%s)", strerror (errno));
        close (sd);
        return RETURNerror;
      }
    }
  }
  return sd;
}
//------------------------------------------------------------------------------
int pfcp_switch::create_pdn_socket (const char * const ifname)
{
  struct sockaddr_in                      addr = {};
  int                                     sd = RETURNerror;

  if (ifname) {
    /*
     * Create socket
     * The  socket_type is either SOCK_RAW for raw packets including the link-level header or SOCK_DGRAM for cooked packets with the link-level header removed.
     */
    if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
      /*
       * Socket creation has failed...
       */
      Logger::pfcp_switch().error( "Socket creation failed (%s)", strerror (errno));
      return RETURNerror;
    }

    int option_on = 1;
    const int *p_option_on = &option_on;
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, p_option_on, sizeof(option_on)) < 0) {
      Logger::pfcp_switch().error("Set header included failed (%s)", strerror (errno));
      close (sd);
      return RETURNerror;
    }

    struct ifreq ifr = {};
    strncpy ((char *) ifr.ifr_name, ifname, IFNAMSIZ);
    if ((setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr))) < 0) {
      Logger::pfcp_switch().error("Socket bind to %s failed (%s)", ifname, strerror (errno));
      close(sd);
      return RETURNerror;
    }
    return sd;
  }
  return RETURNerror;
}
//------------------------------------------------------------------------------
void pfcp_switch::setup_pdn_interfaces()
{
  std::string cmd = fmt::format("ip link set dev {0} down > /dev/null 2>&1; ip link del {0} > /dev/null 2>&1; sync; sleep 1; ip link add {0} type dummy; ethtool -K {0} tx-checksum-ip-generic off; ip link set dev {0} up", PDN_INTERFACE_NAME);
  int rc = system ((const char*)cmd.c_str());

  for (auto it : spgwu_cfg.pdns) {
    if (it.prefix_ipv4) {
      struct in_addr address4 = {};
      address4.s_addr = it.network_ipv4.s_addr + be32toh(1);

      std::string cmd = fmt::format("ip -4 addr add {}/{} dev {}", conv::toString(address4).c_str(), it.prefix_ipv4, PDN_INTERFACE_NAME);
      rc = system ((const char*)cmd.c_str());

      if (it.snat) {
        cmd = fmt::format("iptables -t nat -A POSTROUTING -s {}/{} -j SNAT --to-source {}",
                          conv::toString(address4).c_str(),
                          it.prefix_ipv4,
                          conv::toString(spgwu_cfg.sgi.addr4).c_str());
        rc = system ((const char*)cmd.c_str());
      }
    }
    if (it.prefix_ipv6) {
      std::string cmd = fmt::format("echo 0 > /proc/sys/net/ipv6/conf/{}/disable_ipv6", PDN_INTERFACE_NAME);
      rc = system ((const char*)cmd.c_str());

      struct in6_addr addr6 = it.network_ipv6;
      addr6.s6_addr[15] = 1;
      cmd = fmt::format("ip -6 addr add {}/{} dev {}", conv::toString(addr6).c_str(), it.prefix_ipv6, PDN_INTERFACE_NAME);
      rc = system ((const char*)cmd.c_str());
//      if ((it.snat) && (/* SGI has IPv6 address*/)){
      //        cmd = fmt::format("ip6tables -t nat -A POSTROUTING -s {}/{} -o {} -j SNAT --to-source {}", conv::toString(addr6).c_str(), it.prefix_ipv6, xxx);
//        rc = system ((const char*)cmd.c_str());
//      }
    }
  }

  // Otherwise redirect incoming ingress UE IP to default gw
  rc = system ("/sbin/sysctl -w net.ipv4.conf.all.forwarding=1");
  rc = system ("/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0");
  rc = system ("/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0");
  rc = system ("/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0");
  rc = system ("/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0");

  cmd = fmt::format("/sbin/sysctl -w net.ipv4.conf.{}.send_redirects=0", PDN_INTERFACE_NAME);
  rc = system ((const char*)cmd.c_str());
  cmd = fmt::format("/sbin/sysctl -w net.ipv4.conf.{}.accept_redirects=0", PDN_INTERFACE_NAME);
  rc = system ((const char*)cmd.c_str());


  if ((sock_r = create_pdn_socket(PDN_INTERFACE_NAME, false, pdn_if_index)) <= 0) {
    Logger::pfcp_switch().error("Could not set PDN dummy read socket");
    sleep(2);
    exit(EXIT_FAILURE);
  }

  if ((sock_w = create_pdn_socket(spgwu_cfg.sgi.if_name.c_str())) <= 0) {
    Logger::pfcp_switch().error("Could not set PDN dummy write socket");
    sleep(2);
    exit(EXIT_FAILURE);
  }
}

//------------------------------------------------------------------------------
pfcp::fteid_t pfcp_switch::generate_fteid_s1u()
{
  pfcp::fteid_t fteid = {};
  fteid.teid = generate_teid_s1u();
  if (spgwu_cfg.s1_up.addr4.s_addr) {
    fteid.v4 = 1;
    fteid.ipv4_address.s_addr = spgwu_cfg.s1_up.addr4.s_addr;
  } else {
    fteid.v6 = 1;
    fteid.ipv6_address = spgwu_cfg.s1_up.addr6;
  }
  return fteid;
}
//------------------------------------------------------------------------------
pfcp_switch::pfcp_switch() : seid_generator_(), teid_s1u_generator_(),
    ue_ipv4_hbo2pfcp_pdr(PFCP_SWITCH_MAX_PDRS),
    ul_s1u_teid2pfcp_pdr(PFCP_SWITCH_MAX_PDRS),
    up_seid2pfcp_sessions(PFCP_SWITCH_MAX_SESSIONS),
    if_count(1)
{
  timer_min_commit_interval_id = 0;
  timer_max_commit_interval_id = 0;
  cp_fseid2pfcp_sessions = {},
  msg_iov_.iov_base = &recv_buffer_[ROOM_FOR_GTPV1U_G_PDU]; // make room for GTPU G_PDU header
  msg_iov_.iov_len = PFCP_SWITCH_RECV_BUFFER_SIZE - ROOM_FOR_GTPV1U_G_PDU;
  sock_r = -1;
  sock_w = -1;
  pdn_if_index = -1;
  setup_pdn_interfaces();
  thread_sock_ = thread(&pfcp_switch::pdn_read_loop,this, spgwu_cfg.itti.sx_sched_params);
  thread_sock_.detach();

  if (odp_init_global(&instance, NULL, NULL)) {
    printf("Error: ODP global init failed.\n");
    exit(1);
  }

  if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
    printf("Error: ODP local init failed.\n");
    exit(1);
  }

  /* Reserve memory for args from shared mem */
  shm = odp_shm_reserve("_appl_global_data", sizeof(global_data_t),
            ODP_CACHE_LINE_SIZE, 0);
  if (shm == ODP_SHM_INVALID) {
    printf("Error: shared mem reserve failed.\n");
    exit(EXIT_FAILURE);
  }

  global = (global_data_t *)odp_shm_addr(shm);
  if (global == NULL) {
    printf("Error: shared mem alloc failed.\n");
    exit(EXIT_FAILURE);
  }

  memset(global, 0, sizeof(global_data_t));
  odp_atomic_init_u32(&global->exit_threads, 0);
  global->shm = shm;

}
//------------------------------------------------------------------------------
pfcp_switch::~pfcp_switch()
{
  odp_atomic_store_u32(&global->exit_threads, 1);

  /* wait for other threads to join */
  for (int i = 0; i < nb_worker; i++)
    odph_odpthreads_join(&thread_tbl[i]);

  /* Stop and close used pktio devices */
  for (i = 0; i < if_count; i++) {
    odp_pktio_t pktio = global->l3fwd_pktios[i].pktio;

    if (odp_pktio_stop(pktio) || odp_pktio_close(pktio)) {
      printf("Error: failed to close pktio\n");
      exit(EXIT_FAILURE);
    }
  }

  shm = odp_shm_lookup("flow_table");
  if (shm != ODP_SHM_INVALID && odp_shm_free(shm) != 0) {
    printf("Error: shm free flow_table\n");
    exit(EXIT_FAILURE);
  }
  shm = odp_shm_lookup("shm_fwd_db");
  if (shm != ODP_SHM_INVALID && odp_shm_free(shm) != 0) {
    printf("Error: shm free shm_fwd_db\n");
    exit(EXIT_FAILURE);
  }
  shm = odp_shm_lookup("fib_lpm_sub");
  if (shm != ODP_SHM_INVALID && odp_shm_free(shm) != 0) {
    printf("Error: shm free fib_lpm_sub\n");
    exit(EXIT_FAILURE);
  }

  if (odp_pool_destroy(pool)) {
    printf("Error: pool destroy\n");
    exit(EXIT_FAILURE);
  }

  if (odp_shm_free(global->shm)) {
    printf("Error: shm free global data\n");
    exit(EXIT_FAILURE);
  }

  if (odp_term_local()) {
    printf("Error: term local\n");
    exit(EXIT_FAILURE);
  }

  if (odp_term_global(instance)) {
    printf("Error: term global\n");
    exit(EXIT_FAILURE);
  }
}
//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_session_by_cp_fseid(const pfcp::fseid_t& fseid, std::shared_ptr<pfcp::pfcp_session>& session) const
{
  std::unordered_map<fseid_t, std::shared_ptr<pfcp::pfcp_session>>::const_iterator sit = cp_fseid2pfcp_sessions.find (fseid);
  if (sit == cp_fseid2pfcp_sessions.end()) {
    return false;
  } else {
    session = sit->second;
    return true;
  }
}
//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_session_by_up_seid(const uint64_t cp_seid, std::shared_ptr<pfcp::pfcp_session>& session) const
{
  folly::AtomicHashMap<uint64_t, std::shared_ptr<pfcp::pfcp_session>>::const_iterator sit = up_seid2pfcp_sessions.find (cp_seid);
  if (sit == up_seid2pfcp_sessions.end()) {
    return false;
  } else {
    session = sit->second;
    return true;
  }
}
//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_ul_pdrs_by_up_teid(const teid_t teid, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>& pdrs) const
{
  folly::AtomicHashMap<teid_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>::const_iterator pit = ul_s1u_teid2pfcp_pdr.find (teid);
  if ( pit == ul_s1u_teid2pfcp_pdr.end() )
    return false;
  else {
    pdrs = pit->second;
    return true;
  }
}
//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_dl_pdrs_by_ue_ip(const uint32_t ue_ip, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>& pdrs) const
{
  folly::AtomicHashMap<uint32_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>::const_iterator pit = ue_ipv4_hbo2pfcp_pdr.find (ue_ip);
  if ( pit == ue_ipv4_hbo2pfcp_pdr.end() )
    return false;
  else {
    pdrs = pit->second;
    return true;
  }
}
//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_session_by_cp_fseid(const pfcp::fseid_t& fseid, std::shared_ptr<pfcp::pfcp_session>& session)
{
  std::pair<fseid_t, std::shared_ptr<pfcp::pfcp_session>> entry(fseid, session);
  cp_fseid2pfcp_sessions.insert(entry);
}
//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_session_by_up_seid(const uint64_t seid, std::shared_ptr<pfcp::pfcp_session>& session)
{
  std::pair<uint64_t, std::shared_ptr<pfcp::pfcp_session>> entry(seid, session);
  up_seid2pfcp_sessions.insert(entry);
}
//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_session(std::shared_ptr<pfcp::pfcp_session>& session)
{
  session->cleanup();
  cp_fseid2pfcp_sessions.erase(session->cp_fseid);
  up_seid2pfcp_sessions.erase(session->seid);

}
//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_session(const pfcp::fseid_t& cp_fseid)
{
  std::shared_ptr<pfcp::pfcp_session> session = {};
  if (get_pfcp_session_by_cp_fseid(cp_fseid, session)) {
    remove_pfcp_session(session);
  }
}

//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_ul_pdr_by_up_teid(const teid_t teid, std::shared_ptr<pfcp::pfcp_pdr>& pdr)
{
  folly::AtomicHashMap<teid_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>::const_iterator pit = ul_s1u_teid2pfcp_pdr.find (teid);
  if ( pit == ul_s1u_teid2pfcp_pdr.end() ) {
    std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>> pdrs = std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>(new std::vector<std::shared_ptr<pfcp::pfcp_pdr>>());
    pdrs->push_back(pdr);
    std::pair<teid_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>> entry(teid, pdrs);
    //Logger::pfcp_switch().info( "add_pfcp_ul_pdr_by_up_teid tunnel " TEID_FMT " ", teid);
    ul_s1u_teid2pfcp_pdr.insert(entry);
  } else {
    // sort by precedence
    //const std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>& spdrs = pit->second;
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>>* pdrs = pit->second.get();
    for (std::vector<std::shared_ptr<pfcp::pfcp_pdr>>::iterator it=pdrs->begin(); it < pdrs->end(); ++it) {
      if (*(it->get()) < *(pdr.get())) {
        pit->second->insert(it, pdr);
        return;
      }
    }
  }
}
//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_ul_pdrs_by_up_teid(const teid_t teid)
{
  ul_s1u_teid2pfcp_pdr.erase(teid);
}

//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_dl_pdr_by_ue_ip(const uint32_t ue_ip, std::shared_ptr<pfcp::pfcp_pdr>& pdr)
{
  folly::AtomicHashMap<uint32_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>::const_iterator pit = ue_ipv4_hbo2pfcp_pdr.find (ue_ip);
  if ( pit == ue_ipv4_hbo2pfcp_pdr.end() ) {
    std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>> pdrs = std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>(new std::vector<std::shared_ptr<pfcp::pfcp_pdr>>());
    pdrs->push_back(pdr);
    std::pair<uint32_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>> entry(ue_ip, pdrs);
    ue_ipv4_hbo2pfcp_pdr.insert(entry);
    //Logger::pfcp_switch().info( "add_pfcp_dl_pdr_by_ue_ip UE IP %8x", ue_ip);
  } else {
    // sort by precedence
    //const std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>& spdrs = pit->second;
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>>* pdrs = pit->second.get();
    for (std::vector<std::shared_ptr<pfcp::pfcp_pdr>>::iterator it=pdrs->begin(); it < pdrs->end(); ++it) {
      if (*(it->get()) < *(pdr.get())) {
        pit->second->insert(it, pdr);
        return;
      }
    }
  }
}
//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_dl_pdrs_by_ue_ip(const uint32_t ue_ip)
{
  ue_ipv4_hbo2pfcp_pdr.erase(ue_ip);
}
//------------------------------------------------------------------------------
std::string pfcp_switch::to_string() const
{
  std::string s = {};
  for (const auto& it : up_seid2pfcp_sessions) {
    s.append(it.second->to_string());
  }
  return s;
}

//------------------------------------------------------------------------------
bool pfcp_switch::create_packet_in_access(std::shared_ptr<pfcp::pfcp_pdr>& pdr, const pfcp::fteid_t& in, uint8_t& cause)
{
  cause = CAUSE_VALUE_REQUEST_ACCEPTED;
  add_pfcp_ul_pdr_by_up_teid(in.teid, pdr);
  return true;
}

//------------------------------------------------------------------------------
void pfcp_switch::handle_pfcp_session_establishment_request(std::shared_ptr<itti_sxab_session_establishment_request> sreq, itti_sxab_session_establishment_response* resp)
{
  itti_sxab_session_establishment_request * req = sreq.get();
  pfcp::fseid_t fseid = {};
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};
  pfcp::offending_ie_t offending_ie = {};

  if (req->pfcp_ies.get(fseid)) {
    std::shared_ptr<pfcp::pfcp_session> s = {};
    bool exist = get_pfcp_session_by_cp_fseid(fseid, s);
    pfcp_session* session = nullptr;
    if (not exist) {
      session = new pfcp_session(fseid, generate_seid());

      for (auto it : req->pfcp_ies.create_fars) {
        create_far& cr_far = it;
        if (not session->create(cr_far, cause, offending_ie.offending_ie)) {
          session->cleanup();
          delete session;
          break;
        }
      }

      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        //--------------------------------
        // Process PDR to be created
        cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
        for (auto it : req->pfcp_ies.create_pdrs) {
          create_pdr& cr_pdr = it;
          pfcp::fteid_t allocated_fteid = {};

          pfcp::far_id_t    far_id = {};
          if (not cr_pdr.get(far_id)) {
            //should be caught in lower layer
            cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_FAR_ID;
            session->cleanup();
            delete session;
            break;
          }
          // create pdr after create far
          pfcp::create_far  cr_far = {};
          if (not req->pfcp_ies.get(far_id, cr_far)) {
            //should be caught in lower layer
            cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_CREATE_FAR;
            session->cleanup();
            delete session;
            break;
          }

          if (not session->create(cr_pdr, cause, offending_ie.offending_ie, allocated_fteid)) {
            session->cleanup();
            delete session;
            if (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING) {
              resp->pfcp_ies.set(offending_ie);
            }
            resp->pfcp_ies.set(cause);
            break;
          }
          pfcp::created_pdr created_pdr = {};
          created_pdr.set(cr_pdr.pdr_id.second);
          created_pdr.set(allocated_fteid);
          resp->pfcp_ies.set(created_pdr);
        }
      }

      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        s = std::shared_ptr<pfcp_session>(session);
        add_pfcp_session_by_cp_fseid(fseid, s);
        add_pfcp_session_by_up_seid(session->seid, s);
        //start_timer_min_commit_interval();
        //start_timer_max_commit_interval();

        pfcp::fseid_t up_fseid = {};
        spgwu_cfg.get_pfcp_fseid(up_fseid);
        up_fseid.seid = session->get_up_seid();
        resp->pfcp_ies.set(up_fseid);

        // Register session
        pfcp::node_id_t node_id = {};
        req->pfcp_ies.get(node_id);
        pfcp_associations::get_instance().notify_add_session(node_id, fseid);
      }
    } else {
      cause.cause_value = CAUSE_VALUE_REQUEST_REJECTED;
    }
  } else {
    //should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie.offending_ie = PFCP_IE_F_SEID;
  }
  resp->pfcp_ies.set(cause);
  if ((cause.cause_value == CAUSE_VALUE_MANDATORY_IE_MISSING)
  || (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING)){
    resp->pfcp_ies.set(offending_ie);
  }

#if DEBUG_IS_ON
  std::cout << "\n+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" << std::endl;
  std::cout << "| PFCP switch Packet Detection Rule list ordered by established sessions:                                                                                                                          |" << std::endl;
  std::cout << "+----------------+----+--------+--------+------------+---------------------------------------+----------------------+----------------+-------------------------------------------------------------+" << std::endl;
  std::cout << "|  SEID          |pdr |  far   |predence|   action   |        create outer hdr         tun id| rmv outer hdr  tun id|    UE IPv4     |                                                             |" << std::endl;
  std::cout << "+----------------+----+--------+--------+------------+---------------------------------------+----------------------+----------------+-------------------------------------------------------------+" << std::endl;
  for (const auto& it : up_seid2pfcp_sessions) {
    std::cout << it.second->to_string() << std::endl;
  }
#endif
}
//------------------------------------------------------------------------------
void pfcp_switch::handle_pfcp_session_modification_request(std::shared_ptr<itti_sxab_session_modification_request> sreq, itti_sxab_session_modification_response* resp)
{
  itti_sxab_session_modification_request * req = sreq.get();

  std::shared_ptr<pfcp::pfcp_session> s = {};
  pfcp::fseid_t fseid = {};
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};
  pfcp::offending_ie_t offending_ie = {};
  failed_rule_id_t failed_rule = {};

  if (not get_pfcp_session_by_up_seid(req->seid, s)) {
    cause.cause_value = CAUSE_VALUE_SESSION_CONTEXT_NOT_FOUND;
  } else {
    pfcp::pfcp_session* session = s.get();

    pfcp::fseid_t fseid = {};
    if (req->pfcp_ies.get(fseid)) {
      Logger::pfcp_switch().warn( "TODO check carrefully update fseid in PFCP_SESSION_MODIFICATION_REQUEST");
      session->cp_fseid = fseid;
    }
    resp->seid = session->cp_fseid.seid;

    for (auto it : req->pfcp_ies.remove_pdrs) {
      remove_pdr& pdr = it;
      if (not session->remove(pdr, cause, offending_ie.offending_ie)) {
        if (cause.cause_value == CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
          failed_rule.rule_id_type = FAILED_RULE_ID_TYPE_PDR;
          failed_rule.rule_id_value = pdr.pdr_id.second.rule_id;
          resp->pfcp_ies.set(failed_rule);
          break;
        }
      }
    }
    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.remove_fars) {
        remove_far& far = it;
        if (not session->remove(far, cause, offending_ie.offending_ie)) {
          if (cause.cause_value == CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
            failed_rule.rule_id_type = FAILED_RULE_ID_TYPE_FAR;
            failed_rule.rule_id_value = far.far_id.second.far_id;
            resp->pfcp_ies.set(failed_rule);
            break;
          }
        }
      }
    }

    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.create_fars) {
        create_far& cr_far = it;
        if (not session->create(cr_far, cause, offending_ie.offending_ie)) {
          break;
        }
      }
    }

    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.create_pdrs) {
        create_pdr& cr_pdr = it;

        pfcp::far_id_t    far_id = {};
        if (not cr_pdr.get(far_id)) {
          //should be caught in lower layer
          cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
          offending_ie.offending_ie = PFCP_IE_FAR_ID;
          break;
        }
        // create pdr after create far
        pfcp::create_far  cr_far = {};
        if (not req->pfcp_ies.get(far_id, cr_far)) {
          //should be caught in lower layer
          cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
          offending_ie.offending_ie = PFCP_IE_CREATE_FAR;
          break;
        }

        pfcp::fteid_t allocated_fteid = {};
        if (not session->create(cr_pdr, cause, offending_ie.offending_ie, allocated_fteid)) {
          if (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING) {
            resp->pfcp_ies.set(offending_ie);
          }
          resp->pfcp_ies.set(cause);
          break;
        }
        pfcp::created_pdr created_pdr = {};
        created_pdr.set(cr_pdr.pdr_id.second);
        if (not allocated_fteid.is_zero()) {
          created_pdr.set(allocated_fteid);
        }
        resp->pfcp_ies.set(created_pdr);
      }
    }

    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.update_pdrs) {
        update_pdr& pdr = it;
        uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
        if (not session->update(pdr, cause_value)) {
          failed_rule_id_t failed_rule = {};
          failed_rule.rule_id_type = FAILED_RULE_ID_TYPE_PDR;
          failed_rule.rule_id_value = pdr.pdr_id.rule_id;
          resp->pfcp_ies.set(failed_rule);
        }
      }
      for (auto it : req->pfcp_ies.update_fars) {
        update_far& far = it;
        uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
        if (not session->update(far, cause_value)) {
          cause.cause_value = cause_value;
          failed_rule_id_t failed_rule = {};
          failed_rule.rule_id_type = FAILED_RULE_ID_TYPE_FAR;
          failed_rule.rule_id_value = far.far_id.far_id;
          resp->pfcp_ies.set(failed_rule);
        }
      }
    }
  }
  resp->pfcp_ies.set(cause);
  if ((cause.cause_value == CAUSE_VALUE_MANDATORY_IE_MISSING)
  || (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING)){
    resp->pfcp_ies.set(offending_ie);
  }

#if DEBUG_IS_ON
  std::cout << "\n+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" << std::endl;
  std::cout << "| PFCP switch Packet Detection Rule list ordered by established sessions:                                                                                                                          |" << std::endl;
  std::cout << "+----------------+----+--------+--------+------------+---------------------------------------+----------------------+----------------+-------------------------------------------------------------+" << std::endl;
  std::cout << "|  SEID          |pdr |  far   |predence|   action   |        create outer hdr         tun id| rmv outer hdr  tun id|    UE IPv4     |                                                             |" << std::endl;
  std::cout << "+----------------+----+--------+--------+------------+---------------------------------------+----------------------+----------------+-------------------------------------------------------------+" << std::endl;
  for (const auto& it : up_seid2pfcp_sessions) {
    std::cout << it.second->to_string() << std::endl;
  }
#endif
}
//------------------------------------------------------------------------------
void pfcp_switch::handle_pfcp_session_deletion_request(std::shared_ptr<itti_sxab_session_deletion_request> sreq, itti_sxab_session_deletion_response* resp)
{
  itti_sxab_session_deletion_request * req = sreq.get();

  std::shared_ptr<pfcp::pfcp_session> s = {};
  pfcp::fseid_t fseid = {};
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};
  pfcp::offending_ie_t offending_ie = {};
  failed_rule_id_t failed_rule = {};

  if (not get_pfcp_session_by_up_seid(req->seid, s)) {
    cause.cause_value = CAUSE_VALUE_SESSION_CONTEXT_NOT_FOUND;
  } else {
    resp->seid = s->cp_fseid.seid;
    remove_pfcp_session(s);
  }
  pfcp_associations::get_instance().notify_del_session(fseid);
  resp->pfcp_ies.set(cause);

#if DEBUG_IS_ON
  std::cout << "\n+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" << std::endl;
  std::cout << "| PFCP switch Packet Detection Rule list ordered by established sessions:                                                                                                                          |" << std::endl;
  std::cout << "+----------------+----+--------+--------+------------+---------------------------------------+----------------------+----------------+-------------------------------------------------------------+" << std::endl;
  std::cout << "|  SEID          |pdr |  far   |predence|   action   |        create outer hdr         tun id| rmv outer hdr  tun id|    UE IPv4     |                                                             |" << std::endl;
  std::cout << "+----------------+----+--------+--------+------------+---------------------------------------+----------------------+----------------+-------------------------------------------------------------+" << std::endl;
  for (const auto& it : up_seid2pfcp_sessions) {
    std::cout << it.second->to_string() << std::endl;
  }
#endif
}
//------------------------------------------------------------------------------
void pfcp_switch::pfcp_session_look_up_pack_in_access(struct iphdr* const iph, const std::size_t num_bytes, const endpoint& r_endpoint, const uint32_t tunnel_id)
{
  std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>> pdrs = {};
  if (get_pfcp_ul_pdrs_by_up_teid(tunnel_id, pdrs)) {
    bool nocp = false;
    bool buff = false;
    for (std::vector<std::shared_ptr<pfcp::pfcp_pdr>>::iterator it_pdr = pdrs->begin(); it_pdr < pdrs->end(); ++it_pdr) {
      if ((*it_pdr)->look_up_pack_in_access(iph, num_bytes, r_endpoint, tunnel_id)) {
        std::shared_ptr<pfcp::pfcp_session> ssession = {};
        uint64_t lseid = 0;
        if ((*it_pdr)->get(lseid)) {
          if ( get_pfcp_session_by_up_seid(lseid, ssession)) {
            pfcp::far_id_t far_id = {};
            if ((*it_pdr)->get(far_id)) {
              std::shared_ptr<pfcp::pfcp_far> sfar = {};
              if (ssession->get(far_id.far_id, sfar)) {
                sfar->apply_forwarding_rules(iph, num_bytes, nocp, buff);
              }
            }
          }
        }
        return;
      }
      else {
        Logger::pfcp_switch().info( "pfcp_session_look_up_pack_in_access failed PDR id %4x ", (*it_pdr)->pdr_id.rule_id);
      }
    }
  }
  else {
    //Logger::pfcp_switch().info( "pfcp_session_look_up_pack_in_access tunnel " TEID_FMT " not found", tunnel_id);
    spgwu_s1u_inst->report_error_indication(r_endpoint, tunnel_id);
  }
}
//------------------------------------------------------------------------------
void pfcp_switch::pfcp_session_look_up_pack_in_access(struct ipv6hdr* const ip6h, const std::size_t num_bytes, const endpoint& r_endpoint, const uint32_t tunnel_id)
{
  //TODO
}
//------------------------------------------------------------------------------
void pfcp_switch::pfcp_session_look_up_pack_in_core(const char *buffer, const std::size_t num_bytes)
{
  //Logger::pfcp_switch().info( "pfcp_session_look_up_pack_in_core %d bytes", num_bytes);
  struct iphdr* iph = (struct iphdr*)buffer;
  std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>> pdrs;
  if (iph->version == 4) {
    uint32_t ue_ip = be32toh(iph->daddr);
    if (get_pfcp_dl_pdrs_by_ue_ip(ue_ip, pdrs)) {
      bool nocp = false;
      bool buff = false;
      for (std::vector<std::shared_ptr<pfcp::pfcp_pdr>>::iterator it = pdrs->begin(); it < pdrs->end(); ++it) {
        if ((*it)->look_up_pack_in_core(iph, num_bytes)) {
          std::shared_ptr<pfcp::pfcp_session> ssession = {};
          uint64_t lseid = 0;
          if ((*it)->get(lseid)) {
            if ( get_pfcp_session_by_up_seid(lseid, ssession)) {
              pfcp::far_id_t far_id = {};
              if ((*it)->get(far_id)) {
                std::shared_ptr<pfcp::pfcp_far> sfar = {};
#if TRACE_IS_ON
                Logger::pfcp_switch().trace( "pfcp_session_look_up_pack_in_core %d bytes, far id %08X", num_bytes, far_id);
#endif
                if (ssession->get(far_id.far_id, sfar)) {
#if TRACE_IS_ON
                  Logger::pfcp_switch().trace( "pfcp_session_look_up_pack_in_core %d bytes, got far, far id %08X", num_bytes, far_id);
#endif
                  sfar->apply_forwarding_rules(iph, num_bytes, nocp, buff);
                  if (buff) {
#if TRACE_IS_ON
                    Logger::pfcp_switch().trace( "Buffering %d bytes, far id %08X", num_bytes, far_id);
#endif
                    (*it)->buffering_requested(buffer, num_bytes);
                  }
                  if (nocp) {
#if TRACE_IS_ON
                    Logger::pfcp_switch().trace( "Notify CP %d bytes, far id %08X", num_bytes, far_id);
#endif
                    (*it)->notify_cp_requested(ssession);
                  }
                }
              }
            }
          }
          return;
        }
        else {
          Logger::pfcp_switch().info( "look_up_pack_in_core failed PDR id %4x ", (*it)->pdr_id.rule_id);
        }
      }
    }
    else {
      Logger::pfcp_switch().info( "pfcp_session_look_up_pack_in_core UE IP %8x not found", ue_ip);
    }
  } else if (iph->version == 6) {
    // TODO;
  } else {
    Logger::pfcp_switch().info( "Unknown IP version %d packet", iph->version);
  }
}





