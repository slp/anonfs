/* Node state and file contents for anonfs.

   Copyright (C) 2013 Sergio Lopez
   Based on GNU Hurd tmpfs code by:
      Copyright (C) 2000,01,02 Free Software Foundation, Inc.

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

#include "anonfs.h"
#include <sys/mman.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <hurd/hurd_types.h>
#include <hurd/store.h>

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

unsigned int num_files;
static unsigned int gen;

struct node *all_nodes;

int freed = 0;

error_t
diskfs_alloc_node (struct node *dp, mode_t mode, struct node **npp)
{
  struct disknode *dn;

  dn = calloc (1, sizeof *dn);
  if (dn == 0)
    return ENOSPC;
  spin_lock (&diskfs_node_refcnt_lock);
  if (round_page (anonfs_space_used + sizeof *dn) / vm_page_size
      > anonfs_page_limit)
    {
      spin_unlock (&diskfs_node_refcnt_lock);
      free (dn);
      return ENOSPC;
    }
  dn->gen = gen++;
  ++num_files;
  adjust_used(sizeof *dn);
  spin_unlock (&diskfs_node_refcnt_lock);

  pthread_rwlock_init (&dn->alloc_lock, NULL);
  dn->type = IFTODT (mode & S_IFMT);
  return diskfs_cached_lookup ((ino_t) (uintptr_t) dn, npp);
}

void
diskfs_free_node (struct node *np, mode_t mode)
{
  switch (np->dn->type)
    {
    case DT_REG:
      if (np->dn->u.reg.memobj != NULL) {
        free(np->dn->u.reg.memobj);
      }
      if (np->dn->u.reg.pages != NULL) {
        free(np->dn->u.reg.pages);
	adjust_used(-(np->dn->u.reg.npages * sizeof(size_t)));
      }
      break;
    case DT_DIR:
      assert (np->dn->u.dir.entries == 0);
      break;
    case DT_LNK:
      free (np->dn->u.lnk);
      break;
    }
  *np->dn->hprevp = np->dn->hnext;
  if (np->dn->hnext != 0)
    np->dn->hnext->dn->hprevp = np->dn->hprevp;
  free (np->dn);
  np->dn = 0;

  --num_files;
  adjust_used(-(sizeof *np->dn));
}

void
diskfs_node_norefs (struct node *np)
{
  if (np->dn != 0)
    {
      /* We don't bother to do this in diskfs_write_disknode, since it only
	 ever matters here.  The node state goes back into the `struct
	 disknode' while it has no associated diskfs node.  */

      np->dn->size = np->dn_stat.st_size;
      np->dn->mode = np->dn_stat.st_mode;
      np->dn->nlink = np->dn_stat.st_nlink;
      np->dn->uid = np->dn_stat.st_uid;
      np->dn->author = np->dn_stat.st_author;
      np->dn->gid = np->dn_stat.st_gid;
      np->dn->atime = np->dn_stat.st_atim;
      np->dn->mtime = np->dn_stat.st_mtim;
      np->dn->ctime = np->dn_stat.st_ctim;
      np->dn->flags = np->dn_stat.st_flags;

      switch (np->dn->type)
	{
	case DT_REG:
          assert (np->allocsize % vm_page_size == 0);
          np->dn->u.reg.allocpages = np->allocsize / vm_page_size;
	  break;
	case DT_CHR:
	case DT_BLK:
	  np->dn->u.chr = np->dn_stat.st_rdev;
	  break;
	}

      /* Remove this node from the cache list rooted at `all_nodes'.  */
      *np->dn->hprevp = np->dn->hnext;
      if (np->dn->hnext != 0)
	np->dn->hnext->dn->hprevp = np->dn->hprevp;
      np->dn->hnext = 0;
      np->dn->hprevp = 0;
    }

  free (np);
}

static void
recompute_blocks (struct node *np)
{
  struct disknode *const dn = np->dn;
  struct stat *const st = &np->dn_stat;

  st->st_blocks = sizeof *dn + dn->translen;
  switch (dn->type)
    {
    case DT_REG:
      np->allocsize = dn->u.reg.allocpages * vm_page_size;
      st->st_blocks += np->allocsize;
      break;
    case DT_LNK:
      st->st_blocks += st->st_size + 1;
      break;
    case DT_CHR:
    case DT_BLK:
      st->st_rdev = dn->u.chr;
      break;
    case DT_DIR:
      st->st_blocks += dn->size;
      break;
    }
  st->st_blocks = (st->st_blocks + 511) / 512;
}

/* Fetch inode INUM, set *NPP to the node structure;
   gain one user reference and lock the node.  */
error_t
diskfs_cached_lookup (ino_t inum, struct node **npp)
{
  struct disknode *dn = (void *) (uintptr_t) inum;
  struct node *np;

  assert (npp);

  if (dn->hprevp != 0)		/* There is already a node.  */
    {
      np = *dn->hprevp;
      assert (np->dn == dn);
      assert (*dn->hprevp == np);

      diskfs_nref (np);
    }
  else
    /* Create the new node.  */
    {
      struct stat *st;

      np = diskfs_make_node (dn);
      np->cache_id = (ino_t) (uintptr_t) dn;

      spin_lock (&diskfs_node_refcnt_lock);
      dn->hnext = all_nodes;
      if (dn->hnext)
	dn->hnext->dn->hprevp = &dn->hnext;
      dn->hprevp = &all_nodes;
      all_nodes = np;
      spin_unlock (&diskfs_node_refcnt_lock);

      st = &np->dn_stat;
      memset (st, 0, sizeof *st);
      st->st_fstype = FSTYPE_MEMFS;
      st->st_fsid = getpid ();
      st->st_blksize = vm_page_size;

      st->st_ino = (ino_t) (uintptr_t) dn;
      st->st_gen = dn->gen;

      st->st_size = dn->size;
      st->st_mode = dn->mode;
      st->st_nlink = dn->nlink;
      st->st_uid = dn->uid;
      st->st_author = dn->author;
      st->st_gid = dn->gid;
      st->st_atim = dn->atime;
      st->st_mtim = dn->mtime;
      st->st_ctim = dn->ctime;
      st->st_flags = dn->flags;

      st->st_rdev = 0;
      np->allocsize = 0;
      recompute_blocks (np);
    }

  pthread_mutex_lock (&np->lock);
  *npp = np;
  return 0;
}

error_t
diskfs_node_iterate (error_t (*fun) (struct node *))
{
  error_t err = 0;
  unsigned int num_nodes = 0;
  struct node *node, **node_list, **p;

  spin_lock (&diskfs_node_refcnt_lock);

  /* We must copy everything from the hash table into another data structure
     to avoid running into any problems with the hash-table being modified
     during processing (normally we delegate access to hash-table with
     diskfs_node_refcnt_lock, but we can't hold this while locking the
     individual node locks).  */

  for (node = all_nodes; node != 0; node = node->dn->hnext)
    num_nodes++;

  p = node_list = alloca (num_nodes * sizeof (struct node *));
  for (node = all_nodes; node != 0; node = node->dn->hnext)
    {
      *p++ = node;
      node->references++;
    }

  spin_unlock (&diskfs_node_refcnt_lock);

  p = node_list;
  while (num_nodes-- > 0)
    {
      node = *p++;
      if (!err)
	{
	  pthread_mutex_lock (&node->lock);
	  err = (*fun) (node);
	  pthread_mutex_unlock (&node->lock);
	}
      diskfs_nrele (node);
    }

  return err;
}

/* The user must define this function.  Node NP has some light
   references, but has just lost its last hard references.  Take steps
   so that if any light references can be freed, they are.  NP is locked
   as is the pager refcount lock.  This function will be called after
   diskfs_lost_hardrefs.  */
void
diskfs_try_dropping_softrefs (struct node *np)
{
}

/* The user must define this funcction.  Node NP has some light
   references but has just lost its last hard reference.  NP is locked. */
void
diskfs_lost_hardrefs (struct node *np)
{
}

/* The user must define this function.  Node NP has just acquired
   a hard reference where it had none previously.  It is thus now
   OK again to have light references without real users.  NP is
   locked. */
void
diskfs_new_hardrefs (struct node *np)
{
}

error_t
diskfs_get_translator (struct node *np, char **namep, u_int *namelen)
{
  *namelen = np->dn->translen;
  if (*namelen == 0)
    return 0;
  *namep = malloc (*namelen);
  if (*namep == 0)
    return ENOMEM;
  memcpy (*namep, np->dn->trans, *namelen);
  return 0;
}

error_t
diskfs_set_translator (struct node *np,
		       const char *name, u_int namelen,
		       struct protid *cred)
{
  char *new;
  if (namelen == 0)
    {
      free (np->dn->trans);
      new = 0;
      np->dn_stat.st_mode &= ~S_IPTRANS;
    }
  else
    {
      new = realloc (np->dn->trans, namelen);
      if (new == 0)
	return ENOSPC;
      memcpy (new, name, namelen);
      np->dn_stat.st_mode |= S_IPTRANS;
    }
  adjust_used (namelen - np->dn->translen);
  np->dn->trans = new;
  np->dn->translen = namelen;
  recompute_blocks (np);
  return 0;
}

static error_t
create_symlink_hook (struct node *np, const char *target)
{
  assert (np->dn->u.lnk == 0);
  np->dn_stat.st_size = strlen (target);
  if (np->dn_stat.st_size > 0)
    {
      const size_t size = np->dn_stat.st_size + 1;
      np->dn->u.lnk = malloc (size);
      if (np->dn->u.lnk == 0)
	return ENOSPC;
      memcpy (np->dn->u.lnk, target, size);
      np->dn->type = DT_LNK;
      adjust_used (size);
      recompute_blocks (np);
    }
  return 0;
}
error_t (*diskfs_create_symlink_hook)(struct node *np, const char *target)
     = create_symlink_hook;

static error_t
read_symlink_hook (struct node *np, char *target)
{
  memcpy (target, np->dn->u.lnk, np->dn_stat.st_size + 1);
  return 0;
}
error_t (*diskfs_read_symlink_hook)(struct node *np, char *target)
     = read_symlink_hook;

void
diskfs_write_disknode (struct node *np, int wait)
{
}

void
diskfs_file_update (struct node *np, int wait)
{
  diskfs_node_update (np, wait);
}

error_t
diskfs_node_reload (struct node *node)
{
  return 0;
}

/* The user must define this function.  Truncate locked node NP to be SIZE
   bytes long.  (If NP is already less than or equal to SIZE bytes
   long, do nothing.)  If this is a symlink (and diskfs_shortcut_symlink
   is set) then this should clear the symlink, even if
   diskfs_create_symlink_hook stores the link target elsewhere.  */
error_t
diskfs_truncate (struct node *np, off_t size)
{
  off_t old_size = np->allocsize;
  off_t new_size = round_page (size);    

  if (np->dn->type == DT_LNK)
    {
      free (np->dn->u.lnk);
      adjust_used (size - np->dn_stat.st_size);
      np->dn->u.lnk = 0;
      np->dn_stat.st_size = size;
      return 0;
    }

  if (old_size > new_size)
    {
      assert (np->dn->type == DT_REG);
      
      pthread_rwlock_wrlock (&np->dn->alloc_lock);

      while (old_size > new_size)
	{
	  old_size -= vm_page_size;
	  pool_free_page (np->dn->u.reg.pages[old_size / vm_page_size]);
	}

      np->allocsize = new_size;
      np->dn_stat.st_size = size;
      np->dn_stat.st_blocks += (size - np->allocsize) / 512;

      pthread_rwlock_unlock (&np->dn->alloc_lock);
    }

  return 0;
}

/* The user must define this function.  Grow the disk allocated to locked node
   NP to be at least SIZE bytes, and set NP->allocsize to the actual
   allocated size.  (If the allocated size is already SIZE bytes, do
   nothing.)  CRED identifies the user responsible for the call.  */
error_t
diskfs_grow (struct node *np, off_t size, struct protid *cred)
{
  assert (np->dn->type == DT_REG);

  if (size > np->allocsize)
    {
      off_t old_size;
      off_t new_size;
      size_t page;
      int npages;

      pthread_rwlock_wrlock (&np->dn->alloc_lock);

      old_size = np->allocsize;
      new_size = round_page (size);
      npages = new_size / vm_page_size;

      if (npages > np->dn->u.reg.npages)
	{
	  void *new_pdir;
	  size_t new_len = npages * sizeof(size_t);

	  new_pdir = realloc (np->dn->u.reg.pages, new_len);

	  if (new_pdir == NULL)
	    {
	      pthread_rwlock_unlock (&np->dn->alloc_lock);
	      return ENOSPC;
	    }

	  adjust_used((npages - np->dn->u.reg.npages) * sizeof(size_t));
	  np->dn->u.reg.npages = npages;
	  np->dn->u.reg.pages = new_pdir;
	}

      while (old_size < new_size)
	{
	  if ((page = pool_get_page()) == -1)
	    {
	      np->allocsize = old_size;
	      pthread_rwlock_unlock (&np->dn->alloc_lock);
	      return ENOSPC;
	    }

	  np->dn->u.reg.pages[old_size / vm_page_size] = page;

	  old_size += vm_page_size;
	}

      np->allocsize = new_size;

      pthread_rwlock_unlock (&np->dn->alloc_lock);
    }

  return 0;
}

error_t
diskfs_node_read (struct node *np, off_t offset, char *data, size_t amt)
{
   off_t aligned_offset = trunc_page(offset);
   off_t diff = offset - aligned_offset;
   int left = amt;
   int len;
   char *addr;

   if ((offset + amt) > np->allocsize)
     return EIO;

   pthread_rwlock_rdlock (&np->dn->alloc_lock);

   if (diff)
     {
       addr = pool_get_addr (np->dn->u.reg.pages[aligned_offset / vm_page_size]);
       len = MIN(vm_page_size - diff, left);
       memcpy (data, addr + diff, len);

       left -= len;
       data += len;
       aligned_offset += vm_page_size;
     }

   while (left > 0)
     {
       addr = pool_get_addr (np->dn->u.reg.pages[aligned_offset / vm_page_size]);
       len = MIN(vm_page_size, left);
       memcpy (data, addr, len);

       left -= len;
       data += len;
       aligned_offset += vm_page_size;
     }

   pthread_rwlock_unlock (&np->dn->alloc_lock);

   return 0;
}

error_t
diskfs_node_write (struct node *np, off_t offset, char *data, size_t amt)
{
   off_t aligned_offset = trunc_page(offset);
   off_t diff = offset - aligned_offset;
   int left = amt;
   int len;
   char *addr;

   if ((offset + amt) > np->allocsize)
     return EIO;

   pthread_rwlock_rdlock (&np->dn->alloc_lock);

   if (diff)
     {
       addr = pool_get_addr (np->dn->u.reg.pages[aligned_offset / vm_page_size]);
       len = MIN(vm_page_size - diff, left);
       memcpy(addr + diff, data, len);

       left -= len;
       data += len;
       aligned_offset += vm_page_size;
     }

   while (left > 0)
     {
       addr = pool_get_addr (np->dn->u.reg.pages[aligned_offset / vm_page_size]);
       len = MIN(vm_page_size, left);
       memcpy (addr, data, len);

       left -= len;
       data += len;
       aligned_offset += vm_page_size;
     }

   pthread_rwlock_unlock (&np->dn->alloc_lock);

   return 0;
}

/* The user must define this function.  Return a `struct pager *' suitable
   for use as an argument to diskfs_register_memory_fault_area that
   refers to the pager returned by diskfs_get_filemap for node NP.
   NP is locked.  */
struct pager *
diskfs_get_filemap_pager_struct (struct node *np)
{
  return 0;
}

/* We have no pager of our own, so there is no need to worry about
   users of it, or to shut it down.  */
int
diskfs_pager_users ()
{
  return 0;
}
void
diskfs_shutdown_pager ()
{
}

/* The purpose of this is to decide that it's ok to make the fs read-only.
   Turning a temporary filesystem read-only seem pretty useless.  */
vm_prot_t
diskfs_max_user_pager_prot ()
{
  return VM_PROT_READ;		/* Probable lie that lets us go read-only.  */
}

error_t
diskfs_S_file_get_storage_info (struct protid *cred,
				mach_port_t **ports,
				mach_msg_type_name_t *ports_type,
				mach_msg_type_number_t *num_ports,
				int **ints, mach_msg_type_number_t *num_ints,
				off_t **offsets,
				mach_msg_type_number_t *num_offsets,
				char **data, mach_msg_type_number_t *data_len)
{
  return EINVAL;
}

error_t
_diskfs_rdwr_internal (struct node *np,
                       char *data,
                       off_t offset,
                       size_t *amt,
                       int dir,
                       int notime)
{
  vm_prot_t prot = dir ? (VM_PROT_READ | VM_PROT_WRITE) : VM_PROT_READ;
  error_t err = 0;

  if (dir)
    assert (!diskfs_readonly);

  if (*amt == 0)
    /* Zero-length writes do not update mtime or anything else, by POSIX.  */
    return 0;

  if (!diskfs_check_readonly () && !notime)
    {
      if (dir)
        np->dn_set_mtime = 1;
      else
        np->dn_set_atime = 1;
    }

  if (prot == VM_PROT_READ)
    err = diskfs_node_read (np, offset, data, *amt);
  else
    err = diskfs_node_write (np, offset, data, *amt);

  return err;
}

