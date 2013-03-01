/* Backing store management for anonfs.

   Copyright (C) 2013 Sergio Lopez
   Based on GNU Hurd code by:
      Copyright (C) 1996 Free Software Foundation, Inc.
      Written by Thomas Bushnell, n/BSG.

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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <error.h>

#include <inttypes.h>

#include "anonfs.h"

char *pool;
char *bmap;

/* Number of bytes in bmap */
size_t bmap_len;

size_t pool_len;
size_t pool_free;
size_t pool_hint;

struct mutex bmap_lock;

#define NBBY 8
#define isset(a, i) ((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define setbit(a,i) ((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define clrbit(a,i) ((a)[(i)/NBBY] &= ~(1<<(i)%NBBY))

error_t
init_pool (size_t size)
{
  pool = malloc(size);
  memset(pool, 0, size);
  pool_len = size / vm_page_size;
  pool_free = pool_len;
  pool_hint = 0;

  bmap_len = size / vm_page_size / NBBY;
  bmap = malloc (bmap_len);
  memset(bmap, 0, bmap_len);

  mutex_init(&bmap_lock);

  return 0;
}

int
pool_get_page ()
{
  int i;
  int found;

  mutex_lock (&bmap_lock);

  if (!pool_free)
    {
      mutex_unlock (&bmap_lock);
      printf ("Out of space");
      return -1; 
    }

  found = 0;

  for (i = pool_hint; i < pool_len; ++i)
    {
      if (!isset(bmap, i))
        {
          found = 1;
          setbit(bmap, i);
          break;
        }
    }

  if (!found)
    {
      for (i = 0; i < pool_hint; ++i)
        {
          if (!isset(bmap, i))
            {
              found = 1;
              setbit(bmap, i);
              break;
            }
        }
     }

  if (!found)
    {
      mutex_unlock(&bmap_lock);
      printf("Can't find a hole\n");
      return -1;
    }

  pool_free--;
  pool_hint = i + 1;
  adjust_used(vm_page_size);

  mutex_unlock(&bmap_lock);

  return i;
}

char *
pool_get_addr (int page)
{
  return &pool[page * vm_page_size];
}

void
pool_free_page (int page)
{
  mutex_lock (&bmap_lock);

  memset(&pool[page * vm_page_size], 0, vm_page_size);
  clrbit(bmap, page);
  pool_free++;
  adjust_used(-vm_page_size);

  mutex_unlock (&bmap_lock);
}

