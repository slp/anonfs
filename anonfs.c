/* Main program and global state for anonfs.

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

#include <argp.h>
#include <argz.h>
#include <string.h>
#include <inttypes.h>
#include <error.h>

#include "anonfs.h"
#include <limits.h>
#include <fcntl.h>
#include <hurd.h>
#include <hurd/paths.h>
#include <pthread.h>

char *diskfs_server_name = "anonfs";
char *diskfs_server_version = "0.1";
char *diskfs_extra_version = "GNU Hurd";
char *diskfs_disk_name = "mem";

pthread_spinlock_t anonfs_acct_lock = PTHREAD_SPINLOCK_INITIALIZER;

/* We ain't got to show you no stinkin' sync'ing.  */
int diskfs_default_sync_interval = 0;

/* We must supply some claimed limits, though we don't impose any new ones.  */
int diskfs_link_max = (1ULL << (sizeof (nlink_t) * CHAR_BIT)) - 1;
int diskfs_name_max = 255;	/* dirent d_namlen limit */
int diskfs_maxsymlinks = 8;

/* Yeah, baby, we do it all!  */
int diskfs_shortcut_symlink = 1;
int diskfs_shortcut_chrdev = 1;
int diskfs_shortcut_blkdev = 1;
int diskfs_shortcut_fifo = 1;
int diskfs_shortcut_ifsock = 1;

struct node *diskfs_root_node;
mach_port_t default_pager;

off_t anonfs_page_limit, anonfs_space_used;
mode_t anonfs_root_mode = -1;

error_t
diskfs_set_statfs (struct statfs *st)
{
  fsblkcnt_t pages;

  st->f_type = FSTYPE_MEMFS;
  st->f_fsid = getpid ();

  st->f_bsize = vm_page_size;
  st->f_blocks = anonfs_page_limit;

  spin_lock (&diskfs_node_refcnt_lock);
  st->f_files = num_files;
  pages = round_page (anonfs_space_used) / vm_page_size;
  spin_unlock (&diskfs_node_refcnt_lock);

  st->f_bfree = pages < anonfs_page_limit ? anonfs_page_limit - pages : 0;
  st->f_bavail = st->f_bfree;
  st->f_ffree = st->f_bavail / sizeof (struct disknode); /* Well, sort of.  */

  return 0;
}


error_t
diskfs_set_hypermetadata (int wait, int clean)
{
  /* All the state always just lives in core, so we have nothing to do.  */
  return 0;
}

void
diskfs_sync_everything (int wait)
{
}

error_t
diskfs_reload_global_state ()
{
  return 0;
}

int diskfs_synchronous = 0;

static const struct argp_option options[] =
{
  {"mode", 'm', "MODE", 0, "Permissions (octal) for root directory"},
  {NULL,}
};

struct option_values
{
  off_t size;
  mode_t mode;
};

/* Parse a command line option.  */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* We save our parsed values in this structure, hung off STATE->hook.
     Only after parsing all options successfully will we use these values.  */
  struct option_values *values = state->hook;

  switch (key)
    {
    case ARGP_KEY_INIT:
      state->child_inputs[0] = state->input;
      values = malloc (sizeof *values);
      if (values == 0)
	return ENOMEM;
      state->hook = values;
      values->size = 0;
      values->mode = -1;
      break;
    case ARGP_KEY_FINI:
      free (values);
      state->hook = 0;
      break;

    case 'm':			/* --mode=OCTAL */
      {
	char *end = NULL;
	mode_t mode = strtoul (arg, &end, 8);
	if (end == NULL || end == arg)
	  {
	    argp_error (state, "argument must be an octal number");
	    return EINVAL;
	  }
	if (mode & S_IFMT)
	  {
	    argp_error (state, "invalid bits in mode");
	    return EINVAL;
	  }
	values->mode = mode;
      }
      break;

    case ARGP_KEY_NO_ARGS:
      argp_error (state, "must supply maximum size");
      return EINVAL;

    case ARGP_KEY_ARGS:
      if (state->argv[state->next + 1] != 0)
	{
	  argp_error (state, "too many arguments");
	  return EINVAL;
	}
      else
	{
	  char *end = NULL;
	  intmax_t size = strtoimax (state->argv[state->next], &end, 0);
	  if (end == NULL || end == arg)
	    {
	      argp_error (state, "argument must be a number");
	      return EINVAL;
	    }
	  if (size < 0)
	    {
	      argp_error (state, "negative size not meaningful");
	      return EINVAL;
	    }
	  switch (*end)
	    {
	    case 'g':
	    case 'G':
	      size <<= 10;
	    case 'm':
	    case 'M':
	      size <<= 10;
	    case 'k':
	    case 'K':
	      size <<= 10;
	      break;
	    case '%':
	      {
		/* Set as a percentage of the machine's physical memory.  */
		struct vm_statistics vmstats;
		error_t err = vm_statistics (mach_task_self (), &vmstats);
		if (err)
		  {
		    argp_error (state, "cannot find total physical memory: %s",
				strerror (err));
		    return err;
		  }
		size = round_page ((((vmstats.free_count
				      + vmstats.active_count
				      + vmstats.inactive_count
				      + vmstats.wire_count)
				     * vm_page_size)
				    * size + 99) / 100);
		break;
	      }
	    }
	  size = (off_t) size;
	  if (size < 0)
	    {
	      argp_error (state, "size too large");
	      return EINVAL;
	    }
	  values->size = size;
	}
      break;

    case ARGP_KEY_SUCCESS:
      /* All options parse successfully, so implement ours if possible.  */
      anonfs_page_limit = values->size / vm_page_size;
      anonfs_root_mode = values->mode;
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/* Override the standard diskfs routine so we can add our own output.  */
error_t
diskfs_append_args (char **argz, size_t *argz_len)
{
  error_t err;

  /* Get the standard things.  */
  err = diskfs_append_std_options (argz, argz_len);

  if (!err)
    {
      off_t lim = anonfs_page_limit * vm_page_size;
      char buf[100], sfx;
#define S(n, c) if ((lim & ((1 << n) - 1)) == 0) sfx = c, lim >>= n
      S (30, 'G'); else S (20, 'M'); else S (10, 'K'); else sfx = '\0';
#undef S
      snprintf (buf, sizeof buf, "%Ld%c", lim, sfx);
      err = argz_add (argz, argz_len, buf);
    }

  return err;
}

/* Add our startup arguments to the standard diskfs set.  */
static const struct argp_child startup_children[] =
  {{&diskfs_startup_argp}, {0}};
static struct argp startup_argp = {options, parse_opt, "MAX-BYTES", "\
\v\
MAX-BYTES may be followed by k or K for kilobytes,\n\
m or M for megabytes, g or G for gigabytes.",
				   startup_children};

/* Similarly at runtime.  */
static const struct argp_child runtime_children[] =
  {{&diskfs_std_runtime_argp}, {0}};
static struct argp runtime_argp = {0, parse_opt, 0, 0, runtime_children};

struct argp *diskfs_runtime_argp = (struct argp *)&runtime_argp;

static void *
service_paging_requests (void *arg)
{
  struct port_bucket *pager_bucket = arg;
  for (;;)
    ports_manage_port_operations_multithread (pager_bucket,
					      pager_demuxer,
					      1000 * 60 * 2,
					      1000 * 60 * 10, 0);
  return NULL;
}

int
main (int argc, char **argv)
{
  pthread_t thread;
  error_t err;
  mach_port_t bootstrap, realnode;
  struct stat st;

  err = argp_parse (&startup_argp, argc, argv, ARGP_IN_ORDER, NULL, NULL);
  assert_perror (err);

  task_get_bootstrap_port (mach_task_self (), &bootstrap);
  if (bootstrap == MACH_PORT_NULL)
    error (2, 0, "Must be started as a translator");

  pager_bucket = ports_create_bucket();
  pthread_create(&thread, NULL, service_paging_requests, pager_bucket);

  /* Initialize the diskfs library.  Must come before any other diskfs call. */
  err = diskfs_init_diskfs ();
  if (err)
    error (4, err, "init");

  err = diskfs_alloc_node (0, S_IFDIR, &diskfs_root_node);
  if (err)
    error (4, err, "cannot create root directory");

  diskfs_spawn_first_thread (diskfs_demuxer);

  /* Now that we are all set up to handle requests, and diskfs_root_node is
     set properly, it is safe to export our fsys control port to the
     outside world.  */
  realnode = diskfs_startup_diskfs (bootstrap, 0);
  diskfs_root_node->dn_stat.st_mode = S_IFDIR;

  init_pool (anonfs_page_limit * vm_page_size);

  /* Propagate permissions, owner, etc. from underlying node to
     the root directory of the new (empty) filesystem.  */
  err = io_stat (realnode, &st);
  if (err)
    {
      error (0, err, "cannot stat underlying node");
      if (anonfs_root_mode == -1)
	diskfs_root_node->dn_stat.st_mode |= 0777 | S_ISVTX;
      else
	diskfs_root_node->dn_stat.st_mode |= anonfs_root_mode;
      diskfs_root_node->dn_set_ctime = 1;
      diskfs_root_node->dn_set_mtime = 1;
      diskfs_root_node->dn_set_atime = 1;
    }
  else
    {
      if (anonfs_root_mode == -1)
	{
	  diskfs_root_node->dn_stat.st_mode |= st.st_mode &~ S_IFMT;
	  if (S_ISREG (st.st_mode) && (st.st_mode & 0111) == 0)
	    /* There are no execute bits set, as by default on a plain file.
	       For the virtual directory, set execute bits where read bits are
	       set on the underlying plain file.  */
	    diskfs_root_node->dn_stat.st_mode |= (st.st_mode & 0444) >> 2;
	}
      else
	diskfs_root_node->dn_stat.st_mode |= anonfs_root_mode;
      diskfs_root_node->dn_stat.st_uid = st.st_uid;
      diskfs_root_node->dn_stat.st_author = st.st_author;
      diskfs_root_node->dn_stat.st_gid = st.st_gid;
      diskfs_root_node->dn_stat.st_atim = st.st_atim;
      diskfs_root_node->dn_stat.st_mtim = st.st_mtim;
      diskfs_root_node->dn_stat.st_ctim = st.st_ctim;
      diskfs_root_node->dn_stat.st_flags = st.st_flags;
    }
  diskfs_root_node->dn_stat.st_mode &= ~S_ITRANS;
  diskfs_root_node->dn_stat.st_mode |= S_IROOT;
  diskfs_root_node->dn_stat.st_nlink = 2;

  /* We must keep the REALNODE send right to remain the active
     translator for the underlying node.  */

  pthread_mutex_unlock (&diskfs_root_node->lock);

  /* and so we die, leaving others to do the real work.  */
  pthread_exit (NULL);
  /* NOTREACHED */
  return 0;
}
