/*
 *  obexfs.c: FUSE Filesystem to access OBEX
 *
 *  Copyright (c) 2003-2004 Christian W. Zuckschwerdt <zany@triq.net>
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2 of the License, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 *  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *     
 */
/*
 * Created at:    2003-01-05
 * This really should be a wrapper only. ObexFTPs API needs some more work.
 */

/* strndup */
#define _GNU_SOURCE

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statfs.h>
#include <getopt.h>

#include <obexftp/obexftp.h>
#include <obexftp/client.h>
#include <cobexbfb/cobex_bfb.h>

#define UNUSED(x) x __attribute__((unused))

typedef struct {
	mode_t	mode;
	char	*name;
	off_t	size;
	time_t	mtime;
} ofs_dir_t;

typedef struct {
	char *name;
	time_t	time;
	ofs_dir_t *dir;
} ofs_cache_t;

#define CACHE_SIZE 30
#define CACHE_TIMEOUT 10

static obexftp_client_t *cli = NULL;
static char *tty = NULL; // "/dev/ttyS0";
static int transport = 0;
static char *btaddr = NULL; // "00:11:22:33:44:55";
static int btchannel = 5; // 10;

static int info;
static int body_len;
static char *body_data;

static int xfer_len;
static char *xfer_name;
static char *xfer_data;

static ofs_cache_t cache[CACHE_SIZE];
static int cache_ptr = 0;

static void ofs_info_cb(int event, const char *msg, int len, void *UNUSED(data))
{
        switch (event) {

        case OBEXFTP_EV_ERRMSG:
                break;

        case OBEXFTP_EV_ERR:
                break;
        case OBEXFTP_EV_OK:
                break;

        case OBEXFTP_EV_CONNECTING:
                break;
        case OBEXFTP_EV_DISCONNECTING:
                break;
        case OBEXFTP_EV_SENDING:
                break;
        case OBEXFTP_EV_RECEIVING:
                break;

        case OBEXFTP_EV_LISTENING:
                break;

        case OBEXFTP_EV_CONNECTIND:
                break;
        case OBEXFTP_EV_DISCONNECTIND:
                break;

        case OBEXFTP_EV_INFO:
		info = (int)msg;
                break;

        case OBEXFTP_EV_BODY:
                body_len = len;
		body_data = malloc(len);
		if (body_data)
                        memcpy(body_data, msg, len);
                break;

        case OBEXFTP_EV_PROGRESS:
                break;
        }
}

static int ofs_connect()
{
	static obex_ctrans_t *ctrans = NULL;
        int retry;

        if (cli != NULL)
                return 0;

        if (tty != NULL) {
                /* Custom transport Siemens/Ericsson */
                ctrans = cobex_ctrans (tty);
        }
        else {
                /* No custom transport */
                ctrans = NULL;
        }

        /* Open */
        cli = obexftp_cli_open (transport, ctrans, ofs_info_cb, NULL);
        if(cli == NULL) {
                /* Error opening obexftp-client */
                return -1;
        }

        for (retry = 0; retry < 3; retry++) {

                /* Connect */
                if (obexftp_cli_connect (cli, btaddr, btchannel) >= 0)
                        return 0;
                /* Still trying to connect */
		sleep(1);
        }

        cli = NULL;
        return -1;
}

static void ofs_disconnect()
{
        if (cli != NULL) {
                /* Disconnect */
                (void) obexftp_cli_disconnect (cli);
                /* Close */
                obexftp_cli_close (cli);
        }
	cli = NULL;
}

static time_t ofs_atotime (const char *date)
{
	struct tm tm;

	if (6 == sscanf(date, "%4d%2d%2dT%2d%2d%2d",
			&tm.tm_year, &tm.tm_mday, &tm.tm_mon,
			&tm.tm_hour, &tm.tm_min, &tm.tm_sec)) {
		tm.tm_year -= 1900;
		tm.tm_mon--;
	}
	tm.tm_isdst = 0;

	return mktime(&tm);
}

/* very limited - not multi-byte character save */
static int ofs_parse_list (const char *list, int length)
{
        char *copysz;
        char *line;
        char *p;
        char name[200]; // bad coder
        char mod[200]; // - no biscuits!
        char size[200]; // int would be ok too.

	ofs_dir_t *dir_start;
	ofs_dir_t *dir;
	int i;

        copysz = strndup (list, length); /* hehe there is our sz */

	/* prepare a cache to hold this dir */
	p = copysz;
	for (i = 0; p && *p; p = strchr(++p, '\n')) i++;
	printf("%d cache lines\n", i);
	dir_start = dir = malloc(sizeof(ofs_dir_t) * i);

        for (line = copysz; *line != '\0'; ) {
		
		p = line;
                line = strchr(line, '\n');
		if (!line)
			break;
		*line = '\0';
		line++;
		/* can sscanf skip leading whitespace? */
		while (*p == ' ') p++;

                if (2 == sscanf (p, "<folder name=\"%[^\"]\" modified=\"%[^\"]\"", name, mod)) {
                        dir->mode = S_IFDIR | 0755;
                        dir->name = strdup(name);
			dir->mtime = ofs_atotime(mod);
                        dir->size = 0;
			dir++;
                }
                if (3 == sscanf (p, "<file name=\"%[^\"]\" size=\"%[^\"]\" modified=\"%[^\"]\"", name, size, mod)) {
                        dir->mode = S_IFREG | 0644;
                        dir->name = strdup(name);
			dir->mtime = ofs_atotime(mod);
			dir->size = 0;
			sscanf(size, "%i", &i);
			dir->size = i; /* int to off_t */
			dir++;
                }
                // handle hidden folder!

        }

        free (copysz);
	dir->name = NULL;
	cache[cache_ptr].dir = dir_start;

        return 0;
}
/*
static ofs_dir_t *ofs_dir(const char *path)
{
	int i;
	int prefix;

	prefix = strrchr(path, '/') - path;
	printf("looking for dir %s\n", path);
	for (i = 0; i < cache_ptr; i++) {
		printf("comparing to dir %s (%d)\n", cache[i].name, prefix);
		if (strncmp(path, cache[i].name, prefix) == 0) {
			printf("found dir %s\n", cache[i].name);
			return cache[i].dir;
		}
	}

	return NULL;
}
*/
static int ofs_getattr(const char *path, struct stat *stbuf)
{
	char *p;
	int prefix;
	int i;
	ofs_dir_t *dir;

	if(strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 1;
		stbuf->st_uid = getuid();
		stbuf->st_gid = getgid();
		stbuf->st_size = 0;
		stbuf->st_blocks = 0;
		stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);
		return 0;
	}

	p = strrchr(path, '/');
	prefix = p - path;
	p++;

	printf("looking for dir %s\n", path);
	for (i = 0; i < cache_ptr; i++) {
		printf("comparing to dir %s (%d)\n", cache[i].name, prefix);
		if (strncmp(path, cache[i].name, prefix) == 0) {
			printf("found dir %s\n", cache[i].name);
			/* dir found */
			for (dir = cache[i].dir; dir && dir->name; dir++) {
				if (strcmp(p, dir->name) == 0) {
					printf("found entry %s\n", dir->name);
					stbuf->st_mode = dir->mode;
					stbuf->st_nlink = 1;
					stbuf->st_uid = getuid();
					stbuf->st_gid = getgid();
					stbuf->st_size = dir->size;
					stbuf->st_blocks = 0;
					stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = dir->mtime;
					return 0;
				}
			}
		}
	}
	return -ENOENT;
}

static int ofs_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
	int res = 0;
	ofs_dir_t *dir;

	res = ofs_connect();
	if(res < 0)
		return res; /* errno */

	/* List folder */
	cache[cache_ptr].name = strdup(path);
	printf(">>>>%s<<<<\n", path);
	if (path && strlen (path) >1)
		path++;
	res = obexftp_list(cli, NULL, path);
	if(res <= 0)
		return -1; /* errno */

	ofs_parse_list(body_data, body_len);
	free(body_data);

	for (dir = cache[cache_ptr].dir; dir && dir->name; dir++) {
		res = filler(h, dir->name, S_ISDIR(dir->mode) ? DT_DIR : DT_REG);
		if(res != 0)
			break;
	}
	cache_ptr++;

	printf("<<<<%s>>>>\n", path);
	ofs_disconnect();
	return 0;
}

static int ofs_mkdir(const char *path, mode_t UNUSED(mode))
{
	int res;
	char *p, *tail;

	if(!path || *path != '/')
		return 0;

	tail = strdup(path);

	res = ofs_connect();
	if(res < 0)
		return res; /* errno */

        for (tail++; tail && *tail != '\0'; ) {
		
		p = tail;
                tail = strchr(tail, '/');
		if (tail) {
			*tail = '\0';
			tail++;
		}

		(void) obexftp_setpath(cli, p);
	}

	free(tail);
	ofs_disconnect();
	return 0;
}

static int ofs_unlink(const char *path)
{
	int res;

	res = ofs_connect();
	if(res < 0)
		return res; /* errno */

	path++;
	(void) obexftp_del(cli, path);

	ofs_disconnect();
	return 0;
}


static int ofs_rename(const char *from, const char *to)
{
	int res;
	res = ofs_connect();
	if(res < 0)
		return res; /* errno */

	(void) obexftp_rename(cli, from, to);

	ofs_disconnect();

	return 0;
}

static int ofs_truncate(const char *path, off_t size)
{
	printf("Truncating %s to %lld\n", path, size);

	return 0;
}

/* well RWX for everyone I guess! */
static int ofs_open(const char *UNUSED(path), int UNUSED(flags))
{
    return 0;
}

static int ofs_read(const char *path, char *buf, size_t size, off_t offset)
{
	int res = 0;

	if (!xfer_name || strcmp(path, xfer_name)) {

		xfer_name = strdup(path);
		res = ofs_connect();
		if(res < 0)
			return res; /* errno */

		path++;
		(void) obexftp_get(cli, NULL, path);
		xfer_len = body_len;
		xfer_data = body_data;

		ofs_disconnect();
	}
	printf("reading %s at %lld for %d\n", path, offset, size);
	memcpy(buf, xfer_data + offset, size);

	if (offset + (unsigned)size <= (unsigned)xfer_len)
		return size;
	return xfer_len - offset;
}

static int ofs_write(const char *path, const char *UNUSED(buf), size_t size, off_t offset)
{
	printf("Writing %s at %lld for %d\n", path, offset, size);

	return 0;
}

static int ofs_statfs(struct fuse_statfs *fst)
{
	int res;
	int size, free;

	memset(fst, 0, sizeof(struct fuse_statfs));

	res = ofs_connect();
	if(res < 0)
		return res; /* errno */
 
	/* Retrieve Infos */
	(void) obexftp_info(cli, 0x01);
	size = info;
	(void) obexftp_info(cli, 0x02);
	free = info;
 
	ofs_disconnect();

	fst->block_size = 1;    /* optimal transfer block size */
	fst->blocks = size;   /* total data blocks in file system */
	fst->blocks_free = free;    /* free blocks in fs */

	/* fst->files;    / * total file nodes in file system */
	/* fst->files_free;    / * free file nodes in fs */
	/* fst->namelen;  / * maximum length of filenames */

	return 0;
}

static struct fuse_operations ofs_oper = {
	getattr:	ofs_getattr,
	readlink:	NULL,
	getdir:		ofs_getdir,
	mknod:		NULL,
	mkdir:		ofs_mkdir,
	symlink:	NULL,
	unlink:		ofs_unlink,
	rmdir:		ofs_unlink,
	rename:		ofs_rename,
	link:		NULL,
	chmod:		NULL,
	chown:		NULL,
	truncate:	ofs_truncate,
	utime:		NULL,
	open:		ofs_open,
	read:		ofs_read,
	write:		ofs_write,
	statfs:		ofs_statfs,
	release:	NULL,
	fsync:		NULL
		
};

int main(int argc, char *argv[])
{
	while (1) {
		int option_index = 0;
		int c;
		static struct option long_options[] = {
			{"irda",	no_argument, NULL, 'i'},
			{"bluetooth",	required_argument, NULL, 'b'},
			{"channel",	required_argument, NULL, 'B'},
			{"tty",		required_argument, NULL, 't'},
			{"help",	no_argument, NULL, 'h'},
			{"usage",	no_argument, NULL, 'u'},
			{0, 0, 0, 0}
		};
		
		c = getopt_long (argc, argv, "+ib:B:t:h",
				 long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		
		case 'i':
			transport = OBEX_TRANS_IRDA;
			break;
		
		case 'b':
			transport = OBEX_TRANS_BLUETOOTH;
			if (btaddr != NULL)
				free (btaddr);
       			btaddr = optarg;
			break;
			
		case 'B':
			btchannel = atoi(optarg);
			break;
		
		case 't':
			transport = OBEX_TRANS_CUSTOM;
			if (tty != NULL)
				free (tty);

			if (!strcasecmp(optarg, "irda"))
				tty = NULL;
			else
				tty = optarg;
			break;

		case 'h':
		case 'u':
			printf("Usage: %s [-i | -b <dev> [-B <chan>] | -t <dev>] [-- <fuse options>]\n"
				"Transfer files from/to Mobile Equipment.\n"
				"Copyright (c) 2002-2004 Christian W. Zuckschwerdt\n"
				"\n"
				" -i, --irda                  connect using IrDA transport\n"
				" -b, --bluetooth <device>    connect to this bluetooth device\n"
				" -B, --channel <number>      use this bluetooth channel when connecting\n"
				" -t, --tty <device>          connect to this tty using a custom transport\n\n"
				" -h, --help, --usage         this help text\n\n"
				"Options to fusermount need to be preceeded by two dashes (--).\n"
				"\n",
				argv[0]);
			exit(0);
			break;

		default:
			printf("Try `%s --help' for more information.\n",
				 argv[0]);
			exit(0);
		}
	}

	if (transport == 0) {
	       	fprintf(stderr, "No device selected. Use --help for help.\n");
		exit(0);
	}

	argv[optind-1] = argv[0];
	fuse_main(argc-optind+1, &argv[optind-1], &ofs_oper);
	return 0;
}
