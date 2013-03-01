/* Private data structures for anonfs.

   Copyright (C) 2013 Sergio Lopez
   Based on GNU Hurd tmpfs code by:
      Copyright (C) 2000 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _anonfs_h
#define _anonfs_h 1

#include <hurd/pager.h>
#include <hurd/diskfs.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>

struct disknode
{
  uint_fast8_t type;		/* DT_REG et al */

  unsigned int gen;
  off_t size;
  mode_t mode;
  nlink_t nlink;
  uid_t uid, author;
  gid_t gid;
  struct timespec atime, mtime, ctime;
  unsigned int flags;

  char *trans;
  size_t translen;

  struct pager *pager;

  pthread_rwlock_t alloc_lock;

  union
  {
    char *lnk;			/* malloc'd symlink target */
    struct
    {
      char *memobj;
      size_t *pages;
      size_t npages;
      size_t pages_len;
      size_t allocpages;
    } reg;
    struct
    {
      struct anonfs_dirent *entries;
      struct disknode *dotdot;
    } dir;
    dev_t chr, blk;
  } u;

  struct node *hnext, **hprevp;
};

struct anonfs_dirent
{
  struct anonfs_dirent *next;
  struct disknode *dn;
  int pad;
  uint8_t namelen;
  char name[0];
};

struct user_pager_info
{
  struct node *node;
  vm_prot_t max_prot;
};

struct port_bucket *pager_bucket;

extern unsigned int num_files;
extern off_t anonfs_page_limit, anonfs_space_used;

extern mach_port_t default_pager;

extern pthread_spinlock_t anonfs_acct_lock;

static inline void
adjust_used (off_t change)
{
  spin_lock (&anonfs_acct_lock);
  anonfs_space_used += change;
  spin_unlock (&anonfs_acct_lock);
}

error_t
init_pool (size_t size);

int
pool_get_page ();

char *
pool_get_addr (int page);

void
pool_free_page (int page);

error_t
diskfs_node_read (struct node *np, off_t offset, char *data, size_t amt);

#endif
