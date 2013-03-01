/* Pager support for anonfs.

   Copyright (C) 2013 Sergio Lopez
   Based on GNU Hurd tmpfs code by:
      Copyright (C) 2001 Free Software Foundation, Inc.

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
#include <stdlib.h>
#include <stdio.h>

pthread_spinlock_t node_to_pager_lock = PTHREAD_SPINLOCK_INITIALIZER;

/* Call this to create a FILE_DATA pager and return a send right.
   NODE must be locked.  */
mach_port_t
diskfs_get_filemap (struct node *node, vm_prot_t prot)
{
  mach_port_t right;

  if (node->dn->type != DT_REG)
    {
      errno = EOPNOTSUPP;	/* ? */
      return MACH_PORT_NULL;
    }

  pthread_spin_unlock (&node_to_pager_lock);

  do
    {
      struct pager *pager = node->dn->pager;
      if (pager)
	{
	  /* Because PAGER is not a real reference,
	     this might be nearly deallocated.  If that's so, then
	     the port right will be null.  In that case, clear here
	     and loop.  The deallocation will complete separately. */
	  right = pager_get_port (pager);
	  if (right == MACH_PORT_NULL)
	    node->dn->pager = 0;
	  else
	    pager_get_upi (pager)->max_prot |= prot;
	}
      else
	{
	  struct user_pager_info *upi =
	    malloc (sizeof (struct user_pager_info));
	  upi->node = node;
	  upi->max_prot = prot;
	  diskfs_nref_light (node);
	  node->dn->pager =
	    pager_create (upi, pager_bucket, 0,
			  MEMORY_OBJECT_COPY_DELAY, 0);
	  if (node->dn->pager == 0)
	    {
	      diskfs_nrele_light (node);
	      free (upi);
	      pthread_spin_unlock (&node_to_pager_lock);
	      return MACH_PORT_NULL;
	    }

	  right = pager_get_port (node->dn->pager);
	  ports_port_deref (node->dn->pager);
	}
    }
  while (right == MACH_PORT_NULL);
  mach_port_insert_right (mach_task_self (), right, right,
			  MACH_MSG_TYPE_MAKE_SEND);

  pthread_spin_unlock (&node_to_pager_lock);
  return right;
}

/* The user must define this function.  For pager PAGER, read one
   page from offset PAGE.  Set *BUF to be the address of the page,
   and set *WRITE_LOCK if the page must be provided read-only.
   The only permissible error returns are EIO, EDQUOT, and ENOSPC. */
error_t
pager_read_page (struct user_pager_info *pager,
		 vm_offset_t page,
		 vm_address_t *buf,
		 int *write_lock)
{
  error_t err;
  char *data;

  data = mmap (0, vm_page_size, PROT_READ|PROT_WRITE, MAP_ANON, 0, 0);
  err = diskfs_node_read (pager->node, page, data, vm_page_size);
  if (err)
    {
      munmap(data, vm_page_size);
      return err;
    }

  *buf = (vm_address_t) data;
  *write_lock = 1;

  return 0;
}

/* The user must define this function.  For pager PAGER, synchronously
   write one page from BUF to offset PAGE.  In addition, mfree
   (or equivalent) BUF.  The only permissible error returns are EIO,
   EDQUOT, and ENOSPC. */
error_t
pager_write_page (struct user_pager_info *pager,
		  vm_offset_t page,
		  vm_address_t buf)
{
  fprintf(stderr, "pager_write_page\n");
  fflush(stderr);
  return EIEIO;
}

/* The user must define this function.  A page should be made writable. */
error_t
pager_unlock_page (struct user_pager_info *pager,
		   vm_offset_t address)
{
  fprintf(stderr, "pager_unlock_page\n");
  fflush(stderr);
  return EIEIO;
}

void
pager_notify_evict (struct user_pager_info *pager,
		    vm_offset_t page)
{
  fprintf(stderr, "pager_notify_evict\n");
  fflush(stderr);
}


/* The user must define this function.  It should report back (in
   *OFFSET and *SIZE the minimum valid address the pager will accept
   and the size of the object.   */
error_t
pager_report_extent (struct user_pager_info *pager,
		     vm_address_t *offset,
		     vm_size_t *size)
{
  fprintf(stderr, "pager_report_extent\n");
  fflush(stderr);
  return EIEIO;
}

/* The user must define this function.  This is called when a pager is
   being deallocated after all extant send rights have been destroyed.  */
void
pager_clear_user_data (struct user_pager_info *upi)
{
  struct pager *pager;

  pager = upi->node->dn->pager;
  if (pager && pager_get_upi (pager) == upi)
    upi->node->dn->pager = 0;
  
  free(upi);
}

/* The use must define this function.  This will be called when the ports
   library wants to drop weak references.  The pager library creates no
   weak references itself.  If the user doesn't either, then it's OK for
   this function to do nothing.  */
void
pager_dropweak (struct user_pager_info *p)
{
}
