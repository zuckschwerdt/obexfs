/*
 *  obexautofs.c: FUSE Filesystem to access OBEX with automount
 *
 *  Copyright (c) 2005 Christian W. Zuckschwerdt <zany@triq.net>
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
 * Created at:    2005-09-22
 * This is just a wrapper. ObexFTP API does the real work.
 */

/* strndup */
#define _GNU_SOURCE

/* at least fuse v 2.2 is needed */
#define FUSE_USE_VERSION 22
#include <fuse.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <getopt.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <obexftp/obexftp.h>
#include <obexftp/client.h>
#include <obexftp/uuid.h>
#include <cobexbfb/cobex_bfb.h>

#define UNUSED(x) x __attribute__((unused))

#define DEBUGOUPUT
#ifdef DEBUGOUPUT
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...) do { } while (0)
#endif


typedef struct connection connection_t;
struct connection {
	char *alias;
	int transport;
	char *addr;
	int channel;
	obexftp_client_t *cli;
	connection_t *next;
};

#define SCAN_INTERVAL	2
static time_t last_scan = 0;
static connection_t *connections;


static char *tty = NULL; // "/dev/ttyS0";
static int search_irda = 1;
static int search_bt = 1;
static int search_usb = 1;
static int nonblock = 0;


static int discover_irda(void) { return -1; }

static int discover_usb(void) { return -1; }

static int discover_tty(char *port) { return -1; }

static int discover_bt(void)
{
	inquiry_info *info = NULL;
	bdaddr_t bdaddr, bdswap;
	char name[248];
	int dev_id = 0;
	int num_rsp = 10;
	int flags = 0;
	int length = 8;
	int dd, i;
	connection_t *conn;

	DEBUG("Scanning ...\n");
	num_rsp = hci_inquiry(dev_id, length, num_rsp, NULL, &info, flags);

	if(num_rsp < 0) {
		perror("Inquiry failed.");
		return -1;
	}

	if ((dd = hci_open_dev(dev_id)) < 0) {
		perror("HCI device open failed");
		free(info);
		return -1;
	}
  
	for(i = 0; i < num_rsp; i++) {
		memset(name, 0, sizeof(name));

		bacpy(&bdaddr, &(info+i)->bdaddr);
		baswap(&bdswap, &(info+i)->bdaddr);

		if(hci_read_remote_name(dd, &(info+i)->bdaddr, sizeof(name), name, 10000) < 0) {
			strcpy(name, batostr(&bdswap));
		}

		for (conn = connections; conn; conn = conn->next) {
	       		if (!strcmp(conn->alias, name))
				break;
		}
	
		if (!conn) {
			DEBUG("Adding\t%s\t%s\n", batostr(&bdswap), name);
			conn = calloc(1, sizeof(connection_t));
			if (!conn)
				return -1;
			conn->alias = strdup(name);
			conn->transport = OBEX_TRANS_BLUETOOTH;
			conn->addr = batostr(&bdswap); /* FIXME: do we need strdup? */
			conn->channel = 5;
			//conn->cli = ofs_cli_open(OBEX_TRANS_BLUETOOTH, batostr(&bdswap), 5);
			conn->next = connections;
			connections = conn;
		}
	}
  
	close(dd);
	free(info);
  
	return 0;
}

static int discover_devices(void) {
        if (search_irda)
		discover_irda();
        if (search_bt)
		discover_bt();
        if (search_usb)
		discover_usb();
        if (tty)
		discover_tty(tty);
	return 0;
}
 

typedef struct data_buffer data_buffer_t;
struct data_buffer {
	size_t size;
	char *data;
	int write_mode; /* is this a write buffer? */
};


static char *mknod_dummy = NULL; /* bad coder, no biscuits! */

static int nodal = 0;


/* connection handling operations */

static obexftp_client_t *ofs_cli_open(int transport, char *addr, int channel)
{
	obexftp_client_t *cli;
	obex_ctrans_t *ctrans = NULL;
        int retry;

        if (tty != NULL) {
                /* Custom transport Siemens/Ericsson */
                ctrans = cobex_ctrans (tty);
        }
        else {
                /* No custom transport */
                ctrans = NULL;
        }

        /* Open */
        cli = obexftp_cli_open (transport, ctrans, NULL, NULL);
        if(cli == NULL) {
                /* Error opening obexftp-client */
                return NULL;
        }

        for (retry = 0; retry < 3; retry++) {

                /* Connect */
                if (obexftp_cli_connect (cli, addr, channel) >= 0)
                        return cli;
                /* Still trying to connect */
		sleep(1);
        }

        return NULL;
}

static void ofs_cli_close(obexftp_client_t *cli)
{
        if (cli != NULL) {
                /* Disconnect */
                (void) obexftp_cli_disconnect (cli);
                /* Close */
                obexftp_cli_close (cli);
        }
	cli = NULL;
}

static int ofs_connect(obexftp_client_t *cli)
{
	if (!cli)
		return -1;
	if (nonblock) {
		if (++nodal > 1) {
			nodal--;
			return -EBUSY;
		}
	} else {
		while (++nodal > 1) {
			nodal--;
			sleep(1);
		}
	}
	DEBUG("%s() >>>blocking<<<\n", __func__);
	return 0;
}

static void ofs_disconnect(obexftp_client_t *cli)
{
	nodal--;
	DEBUG("%s() <<<unblocking>>>\n", __func__);
}

static obexftp_client_t *ofs_find_connection(const char *path, char **filepath)
{
	int namelen;
	connection_t *conn;

        if (!path || path[0] != '/') {
		DEBUG("Invalid base path \"%s\"\n", path);
		return NULL;
	}
	
	path++;
        *filepath = strchr(path, '/');
	if (*filepath)
		namelen = *filepath - path;
	else
		namelen = strlen(path);
	
	for (conn = connections; conn; conn = conn->next) {
        	if (!strncmp(conn->addr, path, namelen) || !strncmp(conn->alias, path, namelen)) {
			if (!conn->cli)
				conn->cli = ofs_cli_open(conn->transport, conn->addr, conn->channel);
			return conn->cli;
		}
	}
       	return NULL;
}
 

/* file and directory operations */

static int ofs_getattr(const char *path, struct stat *stbuf)
{
	obexftp_client_t *cli;
	char *filepath;

	stat_entry_t *st;
	int res;

	if(!path || *path == '\0' || !strcmp(path, "/")) {
		/* root */
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 1;
		stbuf->st_uid = getuid();
		stbuf->st_gid = getgid();
		stbuf->st_size = 0;
		stbuf->st_blocks = 0;
		stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);
		return 0;
	}
	
	DEBUG("%s() '%s'\n", __func__, path);

	if (mknod_dummy && !strcmp(path, mknod_dummy)) {
		/* fresh mknod dummy */
		stbuf->st_mode = S_IFREG | 0755;
		stbuf->st_nlink = 1;
		stbuf->st_uid = getuid();
		stbuf->st_gid = getgid();
		stbuf->st_size = 0;
		stbuf->st_blocks = 0;
		stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);
		free(mknod_dummy);
		return 0;
	}

        cli = ofs_find_connection(path, &filepath);
	if (!cli)
		return -ENOENT;
	
	if(!filepath) {
		/* the device entry itself */
		if (strchr(path, ':'))
			stbuf->st_mode = S_IFDIR | 0755;
		else
			stbuf->st_mode = S_IFLNK | 0777;
		stbuf->st_nlink = 1;
		stbuf->st_uid = getuid();
		stbuf->st_gid = getgid();
		stbuf->st_size = 0;
		stbuf->st_blocks = 0;
		stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);
		return 0;
	}
	
	res = ofs_connect(cli);
	if(res < 0)
		return res; /* errno */
	
	st = obexftp_stat(cli, filepath);

	ofs_disconnect(cli);
	
	if (!st)
		return -ENOENT;

	stbuf->st_mode = st->mode;
	stbuf->st_nlink = 1;
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_size = st->size;
	stbuf->st_blksize = 512; /* they expect us to do so... */
	stbuf->st_blocks = (st->size + stbuf->st_blksize) / stbuf->st_blksize;
	stbuf->st_mtime = st->mtime;
	stbuf->st_atime = st->mtime;
	stbuf->st_ctime = st->mtime;

	return 0;
}

static int ofs_readlink (const char *path, char *link, size_t size)
{
	connection_t *conn;

	for (conn = connections; conn; conn = conn->next) {
		if(!strcmp(conn->alias, path + 1)) {
			strcpy(link, conn->addr);
			return 0;
		}
	}
	return -ENOENT;
}

static int ofs_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
	obexftp_client_t *cli;
	char *filepath;
	connection_t *conn;
	
	DIR *dir;
	stat_entry_t *ent;
	struct stat stat;
	int res;
	
	if(!path || *path == '\0' || !strcmp(path, "/")) {
		/* list devices */
		if (last_scan + SCAN_INTERVAL < time(NULL)) {
			discover_devices();
			last_scan = time(NULL);
		}
	
		DEBUG("listing devices...\n");
		for (conn = connections; conn; conn = conn->next) {
			stat.st_mode = DT_DIR;
			res = filler(h, conn->alias, DT_LNK, 0);
			res = filler(h, conn->addr, DT_DIR, 0);
			if(res != 0)
				break;
		}
		return 0;
	}

        cli = ofs_find_connection(path, &filepath);
	if (!cli)
		return -1; /* FIXME */
	
	res = ofs_connect(cli);
	if(res < 0)
		return res; /* errno */

	dir = obexftp_opendir(cli, filepath);
	
	if (!dir) {
		ofs_disconnect(cli);
		return -ENOENT;
	}

	while ((ent = obexftp_readdir(dir)) != NULL) {
		DEBUG("GETDIR:%s\n", ent->name);
		stat.st_mode = S_ISDIR(ent->mode) ? DT_DIR : DT_REG;
		res = filler(h, ent->name, S_ISDIR(ent->mode) ? DT_DIR : DT_REG, 0);
		if(res != 0)
			break;
	}
	obexftp_closedir(dir);

	ofs_disconnect(cli);

	return 0;
}

/* needed for creating files and writing to them */
static int ofs_mknod(const char *path, mode_t UNUSED(mode), dev_t UNUSED(dev))
{
	/* check for access */
	
	/* create dummy for subsequent stat */
	if (mknod_dummy)
		free(mknod_dummy);
	mknod_dummy = strdup(path);

	return 0;
}

static int ofs_mkdir(const char *path, mode_t UNUSED(mode))
{
	obexftp_client_t *cli;
	char *filepath;
	int res;

	if(!path || *path != '/')
		return 0;

        cli = ofs_find_connection(path, &filepath);
	if (!cli)
		return -1; /* FIXME */

	res = ofs_connect(cli);
	if(res < 0)
		return res; /* errno */

	(void) obexftp_setpath(cli, filepath, 1);

	ofs_disconnect(cli);

	return 0;
}

static int ofs_unlink(const char *path)
{
	obexftp_client_t *cli;
	char *filepath;
	int res;

	if(!path || *path != '/')
		return 0;

        cli = ofs_find_connection(path, &filepath);
	if (!cli)
		return -1; /* FIXME */

	res = ofs_connect(cli);
	if(res < 0)
		return res; /* errno */

	(void) obexftp_del(cli, filepath);

	ofs_disconnect(cli);

	return 0;
}


static int ofs_rename(const char *from, const char *to)
{
	obexftp_client_t *cli;
	char *filepath;
	int res;

	if(!from || *from != '/')
		return 0;

	if(!to || *to != '/')
		return 0;

        cli = ofs_find_connection(from, &filepath);
	if (!cli)
		return -1; /* FIXME */

	res = ofs_connect(cli);
	if(res < 0)
		return res; /* errno */

	(void) obexftp_rename(cli, from, to);

	ofs_disconnect(cli);

	return 0;
}

/* needed for overwriting files */
static int ofs_truncate(const char *UNUSED(path), off_t UNUSED(offset))
{
	DEBUG("%s() called. This is a dummy!\n", __func__);
	return 0;
}

/* well RWX for everyone I guess! */
static int ofs_open(const char *UNUSED(path), struct fuse_file_info *fi)
{
	data_buffer_t *wb;
	
	wb = calloc(1, sizeof(data_buffer_t));
	if (!wb)
		return -1;
	fi->fh = (unsigned long)wb;
	
    return 0;
}

static int ofs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *UNUSED(fi))
{
	obexftp_client_t *cli;
	char *filepath;
	data_buffer_t *wb;
	int res = 0;
	int actual;

	if(!path || *path != '/')
		return 0;

	wb = (data_buffer_t *)fi->fh;
	if (!wb->data) {

        	cli = ofs_find_connection(path, &filepath);
		if (!cli)
			return -1; /* FIXME */

		res = ofs_connect(cli);
		if(res < 0)
			return res; /* errno */

		(void) obexftp_get(cli, NULL, filepath);
		wb->size = cli->buf_size;
		wb->data = cli->buf_data; /* would be better to memcpy this */
		//cli->buf_data = NULL; /* now the data is ours -- without copying */

		ofs_disconnect(cli);
	}
	actual = wb->size - offset;
	if (actual > size)
		actual = size;
	DEBUG("reading %s at %lld for %d (peek: %02x\n", path, offset, actual, wb->data[offset]);
	memcpy(buf, wb->data + offset, actual);

	return actual;
}

static int ofs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	data_buffer_t *wb;
	size_t newsize;
	DEBUG("Writing %s at %lld for %d\n", path, offset, size);
	wb = (data_buffer_t *)fi->fh;

	if (!wb)
		return -1;
	
	if (offset + size > wb->size)
		newsize = offset + size;
	else
		newsize = wb->size; /* don't change the buffer size */
	
	if (!wb->data)
		wb->data = malloc(newsize);
	else if (newsize != wb->size)
		wb->data = realloc(wb->data, newsize);
	if (!wb->data)
		return -1;
	wb->size = newsize;
	wb->write_mode = 1;

	DEBUG("memcpy to %ld (%ld) from %ld cnt %ld\n", wb->data + offset, wb->data, buf, size);
	(void) memcpy(&wb->data[offset], buf, size);

	return size;
}

/* careful, this can be a read release or a write release */
static int ofs_release(const char *path, struct fuse_file_info *fi)
{
	obexftp_client_t *cli;
	char *filepath;
	data_buffer_t *wb;
	int res;
	
	wb = (data_buffer_t *)fi->fh;
	DEBUG("Releasing: %s (%ld)\n", path, wb);
	if (wb && wb->data && wb->write_mode) {
		DEBUG("Now writing %s for %d (%02x)\n", path, wb->size, wb->data[0]);

	        cli = ofs_find_connection(path, &filepath);
		if (!cli)
			return -1; /* FIXME */

		res = ofs_connect(cli);
		if(res < 0)
			return res; /* errno */

		(void) obexftp_put_data(cli, wb->data, wb->size, filepath);

		ofs_disconnect(cli);

		free(wb->data);
		free(wb);
	}

	return 0;
}

/* just sum all clients */
static int ofs_statfs(const char *UNUSED(label), struct statfs *st)
{
	connection_t *conn;
	int res;
	int size = 0, free = 0;

        for (conn = connections; conn; conn = conn->next)
		if (conn->cli && ofs_connect(conn->cli) >= 0) {

			/* for S45 */
			(void) obexftp_cli_disconnect (conn->cli);
			(void) obexftp_cli_connect_uuid (conn->cli, conn->addr, conn->channel, UUID_S45);
 
			/* Retrieve Infos */
			(void) obexftp_info(conn->cli, 0x01);
			size += conn->cli->apparam_info;
			(void) obexftp_info(conn->cli, 0x02);
			free += conn->cli->apparam_info;
 
			 DEBUG("%s() GOT FS STAT: %d / %d\n", __func__, free, size);
 
			(void) obexftp_cli_disconnect (conn->cli);
			(void) obexftp_cli_connect (conn->cli, conn->addr, conn->channel);

			ofs_disconnect(conn->cli);
		}

	memset(st, 0, sizeof(struct statfs));
	st->f_bsize = 1;	/* optimal transfer block size */
	st->f_blocks = size;	/* total data blocks in file system */
	st->f_bfree = free;	/* free blocks in fs */
	st->f_bavail = free;	/* free blocks avail to non-superuser */

	/* st->f_files;		/ * total file nodes in file system */
	/* st->f_ffree;		/ * free file nodes in fs */
	/* st->f_namelen;	/ * maximum length of filenames */

	return 0;
}

static void *ofs_init(void) {

        /* Open connection */
	//res = ofs_cli_open();
	//if(res < 0)
	//	return res; /* errno */

       	//discover_bt(&alias, &bdaddr, &channel);
	//ofs_cli_open();
	return NULL;
}

static void ofs_destroy(void *private_data) {
	connection_t *conn;
	
	DEBUG("terminating...\n");
        /* Close connection */
	for (conn = connections; conn; conn = conn->next)
		ofs_cli_close(conn->cli);
	return;
}


/* main */

static struct fuse_operations ofs_oper = {
	getattr:	ofs_getattr,
	readlink:	ofs_readlink,
	opendir:	NULL,
	readdir:	NULL,
	releasedir:	NULL,
	getdir:		ofs_getdir,
	mknod:		ofs_mknod,
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
	release:	ofs_release,
	flush:		NULL,
	fsync:		NULL,
	init:		ofs_init,
	destroy:	ofs_destroy
};

int main(int argc, char *argv[])
{
	int res;
	
	while (1) {
		int option_index = 0;
		int c;
		static struct option long_options[] = {
			{"noirda",	no_argument, NULL, 'I'},
			{"nobluetooth",	no_argument, NULL, 'B'},
			{"nousb",	no_argument, NULL, 'U'},
			{"tty",		required_argument, NULL, 't'},
			{"nonblock",	no_argument, NULL, 'N'},
			{"help",	no_argument, NULL, 'h'},
			{"usage",	no_argument, NULL, 'h'},
			{0, 0, 0, 0}
		};
		
		c = getopt_long (argc, argv, "+IBUt:Nh",
				 long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		
		case 'I':
			search_irda = 0;
			break;
		
		case 'B':
       			search_bt = 0;
			break;
			
		case 'U':
			search_usb = 0;
			break;
		
		case 't':
			if (tty != NULL)
				free (tty);
       			tty = NULL;

			if (strcasecmp(optarg, "irda"))
				tty = optarg;
			break;
			
		case 'N':
			nonblock = 1;
			break;

		case 'h':
			/* printf("ObexFS %s\n", VERSION); */
			printf("Usage: %s [-I] [-B] [-U] [-t <dev>] [-N] [-- <fuse options>]\n"
				"Transfer files from/to Mobile Equipment.\n"
				"Copyright (c) 2002-2005 Christian W. Zuckschwerdt\n"
				"\n"
				" -I, --noirda                dont search for IrDA devices\n"
				" -B, --nobluetooth           dont search for bluetooth devices\n"
				" -U, --nousb                 dont search for usb devices\n"
				" -t, --tty <device>          search for devices at this tty\n\n"
				" -N, --nonblock              nonblocking mode\n\n"
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

	if (!search_irda && !search_bt && !search_usb && !tty) {
	       	fprintf(stderr, "No device selected. Use --help for help.\n");
		exit(0);
	}

	argv[optind-1] = argv[0];
	
	fprintf(stderr, "IrDA searching not available.\n");
	fprintf(stderr, "USB searching not available.\n");
	fprintf(stderr, "TTY searching not available.\n");
	/* loop */
	fuse_main(argc-optind+1, &argv[optind-1], &ofs_oper);

	return 0;
}
