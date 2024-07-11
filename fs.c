/*
Filesystem Lab disigned and implemented by Liang Junkai,RUC
*/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fuse.h>
#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <malloc.h>
#include "disk.h"

#define DIRMODE S_IFDIR|0755
#define REGMODE S_IFREG|0644

#define max(x, y) ((x) > (y) ? (x) : (y))
#define min(x, y) ((x) < (y) ? (x) : (y))

#define printline printf("line: %d\n",__LINE__)

#define PNUM 12
#define FILENAME_LEN 24
#define MAX_FILE_NUM (1 << 15)
#define MAX_FILE_SIZE (1 << 23)
#define BITMAP_POS 1
#define IBITMAP_POS 1
#define DBITMAP1_POS 2
#define DBITMAP2_POS 3
#define BITMAP_NUM 3
#define INODE_TABLE_POS 4
#define INODE_TABLENUM ((MAX_FILE_NUM * sizeof(Inode) + BLOCK_SIZE - 1) / BLOCK_SIZE)
#define DATA_BLOCK_POS (INODE_TABLE_POS + INODE_TABLENUM)
#define MAX_DIR_ENTRY_NUM (BLOCK_SIZE / sizeof(Directory_entry))

typedef struct Superblock{
	int size;	//文件系统的大小
	int inode_num;	//文件系统的inode数
	int free_inode;	//空闲inode数
	int free_block;	//空闲block数
	int inode_start_pos;	//inode表的起始位置
} Superblock;

typedef struct Inode{
	mode_t mode;				// 文件模式
	nlink_t nlink;				// 文件的链接数
	uid_t uid;					// 文件所有者
	gid_t gid;					// 文件所有者的组
	off_t size;					// 文件字节数
	time_t atime;				// 被访问的时间
	time_t mtime;				// 被修改的时间
	time_t ctime;				// 状态改变的时间
	int blocks;					// 文件的块数
	int direct_pointer[PNUM];	// 直接指针
	int indirect_pointer[2];	// 二级间接指针
	char padding[8];		// 对齐！！！否则会在回写磁盘的时候出现块的偏移量+sizeof(Inode)大于BLOCK_SIZE的情况
} Inode;

typedef struct Directory_entry{
	int inode;	//目录文件的inode
	char name[FILENAME_LEN];	//文件名
} Directory_entry;

typedef struct Directory {
	int n_count;
	char name[FILENAME_LEN];	//目录名
	// Directory_entry entry[(BLOCK_SIZE-28) / sizeof(Directory_entry)];
	Directory_entry entry[128];
} Directory;

typedef struct Bitmap{
	unsigned char map[BLOCK_SIZE];
} Bitmap;

Superblock superblock;
Bitmap ibitmap, dbitmap1, dbitmap2;
Directory root_dir;

void init_superblock(Superblock *superblock)
{
	printf("\tinit_superblock is called\n");
	superblock->size = DISK_SIZE;
	superblock->inode_num = MAX_FILE_NUM;
	superblock->free_inode = MAX_FILE_NUM - 1;
	superblock->free_block = BLOCK_NUM - DATA_BLOCK_POS;
	superblock->inode_start_pos = INODE_TABLE_POS;
	char buffer[BLOCK_SIZE];
	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, superblock, sizeof(Superblock));
	disk_write(0, buffer);
}

void write_superblock(Superblock *superblock)
{
	printf("\twrite_superblock is called\n");
	char buffer[BLOCK_SIZE];
	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, superblock, sizeof(Superblock));
	disk_write(0, buffer);
}

void init_inode(Inode *inode, mode_t mode) 
{
	printf("\tinit_inode is called\n");
	inode->mode = mode;
	inode->nlink = 1;
	inode->uid = getuid();
	inode->gid = getgid();
	inode->size = 0;
	inode->atime = time(NULL);
	inode->mtime = time(NULL);
	inode->ctime = time(NULL);
	inode->blocks = 0;
	memset(inode->direct_pointer, -1, sizeof(inode->direct_pointer));
	memset(inode->indirect_pointer, -1, sizeof(inode->indirect_pointer));
}

void set_ibitmap(int inode_id)
{
	ibitmap.map[inode_id / 8] |= 1 << (inode_id % 8);
	char buffer[BLOCK_SIZE];
	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, &ibitmap, sizeof(Bitmap));
	disk_write(IBITMAP_POS, buffer);
}

int get_ibitmap(int inode_id)
{
	char buffer[BLOCK_SIZE];
	memset(buffer, 0, sizeof(buffer));
	disk_read(IBITMAP_POS, buffer);
	memcpy(&ibitmap, buffer, sizeof(Bitmap));
	return (ibitmap.map[inode_id / 8] >> (inode_id % 8)) & 1;
}

void set_dbitmap(int data_block_id)
{
	if (data_block_id < BLOCK_NUM / 2) {
		dbitmap1.map[data_block_id / 8] |= (1 << (data_block_id % 8));
	} else {
		dbitmap2.map[(data_block_id - BLOCK_NUM) / 8] |= (1 << ((data_block_id - BLOCK_NUM) % 8));
	}
	char buffer1[BLOCK_SIZE];
	memset(buffer1, 0, sizeof(buffer1));
	memcpy(buffer1, &dbitmap1, sizeof(Bitmap));
	disk_write(DBITMAP1_POS, buffer1);
	char buffer2[BLOCK_SIZE];
	memset(buffer2, 0, sizeof(buffer2));
	memcpy(buffer2, &dbitmap2, sizeof(Bitmap));
	disk_write(DBITMAP2_POS, buffer2);
}

int get_dbitmap(int data_block_id)
{
	char buffer1[BLOCK_SIZE];
	memset(buffer1, 0, sizeof(buffer1));
	disk_read(DBITMAP1_POS, buffer1);
	memcpy(&dbitmap1, buffer1, sizeof(Bitmap));
	char buffer2[BLOCK_SIZE];
	memset(buffer2, 0, sizeof(buffer2));
	disk_read(DBITMAP2_POS, buffer2);
	memcpy(&dbitmap2, buffer2, sizeof(Bitmap));
	if (data_block_id < BLOCK_NUM / 2) {
		return (dbitmap1.map[data_block_id / 8] >> (data_block_id % 8)) & 1;
	} else {
		return (dbitmap2.map[(data_block_id - BLOCK_NUM) / 8] >> ((data_block_id - BLOCK_NUM) % 8)) & 1;
	}
}

void init_ibitmap()
{
	printf("\tinit_ibitmap is called\n");
	memset(ibitmap.map, 0, sizeof(ibitmap.map));
	set_ibitmap(0);	// root directory
	char buffer[BLOCK_SIZE];
	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, &ibitmap, sizeof(Bitmap));
	disk_write(IBITMAP_POS, buffer);
}

void init_dbitmap()
{
	printf("\tinit_dbitmap is called\n");
	memset(dbitmap1.map, 0, sizeof(dbitmap1.map));
	memset(dbitmap2.map, 0, sizeof(dbitmap2.map));
	char buffer1[BLOCK_SIZE];
	memset(buffer1, 0, sizeof(buffer1));
	memcpy(buffer1, &dbitmap1, sizeof(Bitmap));
	disk_write(DBITMAP1_POS, buffer1);
	char buffer2[BLOCK_SIZE];
	memset(buffer2, 0, sizeof(buffer2));
	memcpy(buffer2, &dbitmap2, sizeof(Bitmap));
	disk_write(DBITMAP2_POS, buffer2);
	for (int i = 0; i < DATA_BLOCK_POS; i++) {
		set_dbitmap(i);
	}
}

/* 获取空闲块，获取到的就是最终的块的位置，并且会设置好位图 */
int get_free_block()
{
	printf("\tget_free_block is called\n");
	int free_block = -1;
	for (int i = 0; i < BLOCK_NUM; i++) {
		if (i < DATA_BLOCK_POS) {
			continue;
		}
		if (!get_dbitmap(i)) {
			set_dbitmap(i);
			free_block = i;
			break;
		}
	}
	if (free_block != -1) {
		superblock.free_block--;
		write_superblock(&superblock);
	}
	return free_block;
}

/* 获取空闲inode，获取到的inode就是最终的inode的位置，并且会设置好位图 */
int get_free_inode()
{
	printf("\tget_free_inode is called\n");
	int free_inode = -1;
	for (int i = 0; i < MAX_FILE_NUM; i++) {
		if (!get_ibitmap(i)) {
			set_ibitmap(i);
			free_inode = i;
			break;
		}
	}
	if (free_inode != -1) {
		superblock.free_inode--;
		write_superblock(&superblock);
	}
	return free_inode;
}

/* 将inode_id对应的inode写到磁盘中，也就是更新ibitmap和inode table */
void write_inode_to_disk(int inode_id, Inode *inode)
{
	printf("\twrite_inode_to_disk is called\n");
	char buffer[BLOCK_SIZE];
	memset(buffer, 0, sizeof(buffer));
	int block_id = INODE_TABLE_POS + (inode_id * sizeof(Inode)) / BLOCK_SIZE;
	int offset = (inode_id * sizeof(Inode)) % BLOCK_SIZE;
	disk_read(block_id, buffer);
	printf("\tblock_id: %d\n", block_id);
	printf("\toffset: %d\n", offset);
	memcpy(buffer + offset, inode, sizeof(Inode));
	disk_write(block_id, buffer);
	set_ibitmap(inode_id);
}

/* 从磁盘中读取inode_id对应的inode，并将获取到的inode table中的内容放到参数inode中 */
void read_inode_from_disk(int inode_id, Inode *inode)
{
	printf("\tread_inode_from_disk is called\n");
	char buffer[BLOCK_SIZE];
	memset(buffer, 0, sizeof(buffer));
	int block_id = INODE_TABLE_POS + (inode_id * sizeof(Inode)) / BLOCK_SIZE;
	int offset = (inode_id * sizeof(Inode)) % BLOCK_SIZE;
	disk_read(block_id, buffer);
	memcpy(inode, buffer + offset, sizeof(Inode));
}

void init_directory()
{
	printf("\tinit_directory is called\n");
	root_dir.n_count = 1;
	strcpy(root_dir.name, "/");
	strcpy(root_dir.entry[0].name, ".");
	root_dir.entry[0].inode = 0;
	Inode root_inode;
	init_inode(&root_inode, DIRMODE);
	root_inode.direct_pointer[0] = get_free_block();	// 这一步分配了位图
	write_inode_to_disk(0, &root_inode);	// 更新磁盘中的inode table
}

void init_filesystem()
{
	printf("\tinit_filesystem is called\n");
	init_superblock(&superblock);
	init_ibitmap();
	init_dbitmap();
	init_directory();
}

/* 从磁盘中读取dir_block_id处的（可能的）dir，并将其存到参数dir中 */
void read_directory_from_disk(int dir_block_id, Directory *dir)
{
	printf("\tread_directory is called\n");
	char buffer[BLOCK_SIZE];
	memset(buffer, 0, sizeof(buffer));
	disk_read(dir_block_id, buffer);
	printf("\tblock_id: %d\n", dir_block_id);
	printf("\tsizeof Directory: %d\n", sizeof(Directory));
	memcpy(dir, buffer, sizeof(Directory));
}

/* 初始化inode->indirect_pointer[idx]，如果还未初始化，就给它分配一个块 */
int init_indirect_pointer(Inode *inode, int idx)
{
	printf("\tinit_indirect_pointer is called\n");
	if (inode->indirect_pointer[idx] == -1) {
		inode->indirect_pointer[idx] = get_free_block();
		if (inode->indirect_pointer[idx] == -1) {
			return -1;
		}
		int block_id = inode->indirect_pointer[idx];
		char buffer[BLOCK_SIZE];
		memset(buffer, 0, sizeof(buffer));
		disk_write(block_id, buffer);
	}
	return 0;
}

void read_indirect_pointer(Inode *inode, int idx, int *indirect_pointer)
{
	printf("\tread_indirect_pointer is called\n");
	int block_id = inode->indirect_pointer[idx];
	if (block_id == -1) {
		block_id = get_free_block();
	}
	char buffer[BLOCK_SIZE];
	memset(buffer, 0, sizeof(buffer));
	disk_read(block_id, buffer);
	memcpy(indirect_pointer, buffer, sizeof(int) * BLOCK_SIZE / sizeof(int));
}

/* 通过inode_id来获取inode */
Inode get_inode_by_id(int inode_id)
{
	printf("\tget_inode_by_id is called\n");
	Inode inode;
	int block_id = INODE_TABLE_POS + (inode_id * sizeof(Inode)) / BLOCK_SIZE;
	int offset = (inode_id * sizeof(Inode)) % BLOCK_SIZE;
	char buffer[BLOCK_SIZE];
	memset(buffer, 0, sizeof(buffer));
	disk_read(block_id, buffer);
	memcpy(&inode, buffer + offset, sizeof(Inode));
	return inode;
}


int get_inode_by_file_name(const char *file_name, int parent_inode_id)
{
	printf("\tget_inode_by_file_name is called\n");
	if (parent_inode_id == -1) {
		return -1;
	}
	Inode parent_inode = get_inode_by_id(parent_inode_id);
	for (int i = 0; i < parent_inode.blocks; i++) {
		Directory dir;
		read_directory_from_disk(parent_inode.direct_pointer[i], &dir);
		for (int j = 0; j < dir.n_count; j++) {
			if (strcmp(dir.entry[j].name, file_name) == 0) {
				return dir.entry[j].inode;
			}
		}
	}
	// 如果在直接指针中没有找到，就继续搜索间接指针
	for (int i = 0; i < 2; i++) {
		int pointers[BLOCK_SIZE];
		read_indirect_pointer(&parent_inode, i, pointers);
		for (int j = 1; j <= pointers[0]; j++)
		{
			Directory dir;
			read_directory_from_disk(pointers[j], &dir);
			for (int k = 0; k < dir.n_count; k++) {
				if (strcmp(dir.entry[k].name, file_name) == 0) {
					return dir.entry[k].inode;
				}
			}
		}
	}
	return -1;
}

/* 通过路径获取inode，并将得到的inode存到参数inode中，返回值是获取到的inode_id */
int get_inode_by_path(const char *path, Inode *inode)
{
	printf("\tget_inode_by_path is called\n");
	int current_inode_id = 0;
	int parent_inode_id;
	char *path_copy = strdup(path);
	char *token = strtok(path_copy, "/");
	while (token != NULL) {
		parent_inode_id = current_inode_id;
		current_inode_id = get_inode_by_file_name(token, parent_inode_id);
		token = strtok(NULL, "/");
	}
	free(path_copy);
	if (inode != NULL) {
		*inode = get_inode_by_id(current_inode_id);
	}
	return current_inode_id;
}

char* get_parent_path(const char *path)
{
	printf("\tget_parent_path is called\n");
	char *path_copy = strdup(path);
	char *parent_path = dirname(path_copy);
	printf("\tparent_path: %s\n", parent_path);
	return parent_path;
}

int get_parent_inode(const char *path)
{
	printf("\tget_parent_inode is called\n");
	char *parent_path = get_parent_path(path);
	int parent_inode = get_inode_by_path(parent_path, 0);
	free(parent_path);
	return parent_inode;
}


void delete_data_from_dbitmap(int data_block_id)
{
	printf("\tdelete_data_from_dbitmap is called\n");
	if (data_block_id < BLOCK_NUM / 2) {
		dbitmap1.map[data_block_id / 8] &= ~(1 << (data_block_id % 8));
	} else {
		dbitmap2.map[(data_block_id - BLOCK_NUM) / 8] &= ~(1 << ((data_block_id - BLOCK_NUM) % 8));
	}
	char buffer1[BLOCK_SIZE];
	memset(buffer1, 0, sizeof(buffer1));
	memcpy(buffer1, &dbitmap1, sizeof(Bitmap));
	disk_write(DBITMAP1_POS, buffer1);
	char buffer2[BLOCK_SIZE];
	memset(buffer2, 0, sizeof(buffer2));
	memcpy(buffer2, &dbitmap2, sizeof(Bitmap));
	disk_write(DBITMAP2_POS, buffer2);
	superblock.free_block++;
	write_superblock(&superblock);
}

void delete_inode_from_ibitmap(int inode_id)
{
	printf("\tdelete_inode_from_ibitmap is called\n");
	Inode inode = get_inode_by_id(inode_id);
	for (int i = 0; i < inode.blocks; i++) {
		delete_data_from_dbitmap(inode.direct_pointer[i]);
	}
	for (int i = 0; i < 2; i++) {
		if (inode.indirect_pointer[i] == -1) {
			continue;
		}
		int pointers[BLOCK_SIZE];
		read_indirect_pointer(&inode, i, pointers);
		for (int j = 1; j <= pointers[0]; j++) {
			delete_data_from_dbitmap(pointers[j]);
		}
	}
	ibitmap.map[inode_id / 8] &= ~(1 << (inode_id % 8));
	char buffer[BLOCK_SIZE];
	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, &ibitmap, sizeof(Bitmap));
	disk_write(IBITMAP_POS, buffer);
	superblock.free_inode++;
	write_superblock(&superblock);
}

int read_file_start_block(Inode *inode, int start_block_id, char *buffer, off_t offset)
{
	printf("\tread_file_start_block is called\n");
	char start_block[BLOCK_SIZE];
	memset(start_block, 0, sizeof(start_block));
	disk_read(start_block_id, start_block);
	memcpy(buffer, start_block + offset, BLOCK_SIZE - offset);
	return BLOCK_SIZE - offset;
}

int read_file_end_block(Inode *inode, int end_block_id, char *buffer, off_t size)
{
	printf("\tread_file_end_block is called\n");
	char end_block[BLOCK_SIZE];
	memset(end_block, 0, sizeof(end_block));
	disk_read(end_block_id, end_block);
	memcpy(buffer, end_block, size);
	return size;
}

int write_file_to_block(Inode *inode, int block_id, const char *buffer, off_t size, off_t offset)
{
	printf("\twrite_file_to_block is called\n");
	char block[BLOCK_SIZE];
	memset(block, 0, sizeof(block));
	disk_read(block_id, block);
	memcpy(block + offset, buffer, size);
	block[size + offset] = '\0';
	disk_write(block_id, block);
	return size;
}

int write_direntry_to_block(Directory_entry *entry, int block_id)
{
	printf("\twrite_direntry_to_block is called\n");
	Directory dir;
	read_directory_from_disk(block_id, &dir);
	if (dir.n_count >= MAX_DIR_ENTRY_NUM) {
		return -1;
	} else {
		dir.entry[dir.n_count] = *entry;
		dir.n_count++;
		char buffer[BLOCK_SIZE];
		memset(buffer, 0, sizeof(buffer));
		memcpy(buffer, &dir, sizeof(Directory));
		disk_write(block_id, buffer);
		return 0;
	
	}
}

int write_direntry_to_indirect(Directory_entry *entry, Inode *inode, int idx)
{
	printf("\twrite_direntry_to_indirect is called\n");
	int pointers[BLOCK_SIZE];
	read_indirect_pointer(inode, idx, pointers);
	if (pointers[0] >= BLOCK_SIZE / sizeof(int) - 1) {
		return -1;
	}
	if (pointers[0] != 0) {
		if (write_direntry_to_block(entry, pointers[pointers[0]]) == 0) {
			return 0;
		}
	}
	pointers[0]++;
	pointers[pointers[0]] = get_free_block();
	if (pointers[pointers[0]] == -1) {
		return -1;
	}
	if (write_direntry_to_block(entry, pointers[pointers[0]]) == 0) {
		char buffer[BLOCK_SIZE];
		memset(buffer, 0, sizeof(buffer));
		memcpy(buffer, pointers, BLOCK_SIZE);
		disk_write(inode->indirect_pointer[idx], buffer);
		return 0;
	}
	return -1;
}

int write_direntry_to_dir(Directory_entry *entry, int dir_inode_id)
{
	printf("\twrite_direntry_to_dir is called\n");
	Inode dir_inode = get_inode_by_id(dir_inode_id);
	dir_inode.mtime = time(NULL);
	dir_inode.ctime = time(NULL);
	if (dir_inode.blocks == 1) {
		dir_inode.blocks++;
		dir_inode.direct_pointer[1] = get_free_block();
		write_inode_to_disk(dir_inode_id, &dir_inode);
	}
	if (dir_inode.blocks < PNUM) {
		int block_id = dir_inode.direct_pointer[dir_inode.blocks-1];
		if (write_direntry_to_block(entry, block_id) == 0) {
			return 0;
		} else if (dir_inode.blocks < PNUM - 1) {
			dir_inode.blocks++;
			dir_inode.direct_pointer[dir_inode.blocks-1] = get_free_block();
			block_id = dir_inode.direct_pointer[dir_inode.blocks-1];
			write_inode_to_disk(dir_inode_id, &dir_inode);
			return write_direntry_to_block(entry, block_id);
		}
	}
	for (int i = 0; i < 2; i++) {
		if (init_indirect_pointer(&dir_inode, 1) == -1) {
			return -1;
		}
		if (write_direntry_to_indirect(entry, &dir_inode, i) == 0) {
			return 0;
		}
	}
}

int allocate_direct_pointer_blocks(Inode *inode, int block_num)
{
	for (int i = block_num; i < PNUM; i++) {
		inode->direct_pointer[i] = get_free_block();
		if (inode->direct_pointer[i] == -1) {
			return -1;
		}
	}
	return 0;
}

int update_indirect_pointer_block(Inode *inode, int *pointers, int block_num, int idx)
{
	if (pointers[0] >= block_num) {
		pointers[0] = block_num;
		char buffer[BLOCK_SIZE];
		memset(buffer, 0, sizeof(buffer));
		memcpy(buffer, pointers, BLOCK_SIZE);
		disk_write(inode->indirect_pointer[idx], buffer);
		return 0;
	}
	for (int i = pointers[0] + 1; i < block_num; i++) {
		pointers[i] = get_free_block();
		if (pointers[i] == -1) {
			return -1;
		}
	}
	pointers[0] = block_num;
	char buffer[BLOCK_SIZE];
	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, pointers, BLOCK_SIZE);
	disk_write(inode->indirect_pointer[idx], buffer);
	return 0;
}

int reconstruct_indirect_pointer(Inode *inode, off_t size)
{
	int pointers[BLOCK_SIZE];
	int block_num = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
	int current_block_num = inode->blocks;
	if (current_block_num < PNUM) {
		if (allocate_direct_pointer_blocks(inode, block_num) == -1) {
			return -1;
		}
	}
	inode->blocks = PNUM;
	block_num -= PNUM;
	init_indirect_pointer(inode, 0);
	read_indirect_pointer(inode, 0, pointers);
	if (pointers[0] < (BLOCK_SIZE / sizeof(int))) {
		if (update_indirect_pointer_block(inode, pointers, block_num, 0) == 0) {
			return 0;
		}
	} else {
		for (int i = pointers[0] + 1; i < (BLOCK_SIZE / sizeof(int)) - 1; i++) {
			pointers[i] = get_free_block();
			if (pointers[i] == -1) {
				return -1;
			}
		}
		pointers[0] = (BLOCK_SIZE / sizeof(int)) - 1;
		char buffer[BLOCK_SIZE];
		memset(buffer, 0, sizeof(buffer));
		memcpy(buffer, pointers, BLOCK_SIZE);
		disk_write(inode->indirect_pointer[0], buffer);
		block_num -= (BLOCK_SIZE / sizeof(int)) - 1;
		init_indirect_pointer(inode, 1);
		read_indirect_pointer(inode, 1, pointers);
		if (update_indirect_pointer_block(inode, pointers, block_num, 1) == 0) {
			return 0;
		}
	}
	return 0;
}

//Format the virtual block device in the following function
int mkfs()
{
	printf("Mkfs is called\n");
	init_filesystem();
	printf("DATA_BLOCK_POS: %d\n", DATA_BLOCK_POS);
	return 0;
}

//Filesystem operations that you need to implement
int fs_getattr (const char *path, struct stat *attr)
{
	printf("Getattr is called:%s\n",path);
	int inode_id = get_inode_by_path(path, NULL);
	if (inode_id == -1) {
		return -ENOENT;
	}
	Inode inode = get_inode_by_id(inode_id);
	attr->st_mode = inode.mode;
	attr->st_nlink = 1;
	attr->st_uid = getuid();
	attr->st_gid = getgid();
	attr->st_size = inode.size;
	attr->st_atime = inode.atime;
	attr->st_mtime = inode.mtime;
	attr->st_ctime = inode.ctime;
	return 0;
}

int fs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	printf("Readdir is called:%s\n", path);
	Inode inode;
	int inode_id = get_inode_by_path(path, &inode);
	if (inode_id == -1) {
		return -ENOENT;
	}
	inode.atime = time(NULL);
	write_inode_to_disk(inode_id, &inode);
	for (int i = 0; i < inode.blocks; i++) {
		Directory dir;
		read_directory_from_disk(inode.direct_pointer[i], &dir);
		for (int j = 0; j < dir.n_count; j++) {
			filler(buffer, dir.entry[j].name, NULL, 0);
		}
	}
	for (int i = 0; i < 2; i++) {
		int pointers[BLOCK_SIZE];
		read_indirect_pointer(&inode, i, pointers);
		for (int j = 1; j <= pointers[0]; j++) {
			Directory dir;
			read_directory_from_disk(pointers[j], &dir);
			for (int k = 0; k < dir.n_count; k++) {
				filler(buffer, dir.entry[k].name, NULL, 0);
			}
		}
	}
	return 0;
}

int fs_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
	printf("Read is called:%s\n",path);
	printf("\tsize: %d\n", size);
	Inode inode;
	int inode_id = get_inode_by_path(path, &inode);
	if (inode_id == -1) {
		return -ENOENT;
	}
	int final_size = 0;
	inode.atime = time(NULL);
	int start_block_id = offset / BLOCK_SIZE + DATA_BLOCK_POS;
	int end_block_id = (offset + size - 1) / BLOCK_SIZE + DATA_BLOCK_POS;
	int start_offset = offset % BLOCK_SIZE;
	int end_offset = (offset + size - 1) % BLOCK_SIZE;
	printf("\tstart_block_id: %d\n", start_block_id);
	printf("\tend_block_id: %d\n", end_block_id);
	for (int i = start_block_id; i <= end_block_id; i++) {
		if (i == start_block_id && i == end_block_id) {
			final_size += read_file_start_block(&inode, i, buffer, start_offset);
		} else if (i == start_block_id) {
			final_size += read_file_start_block(&inode, i, buffer, start_offset);
		} else if (i == end_block_id) {
			final_size += read_file_end_block(&inode, i, buffer + final_size, end_offset + 1);
		} else {
			final_size += read_file_start_block(&inode, i, buffer + final_size, 0);
		}
	}
	return final_size;
}

int fs_mknod (const char *path, mode_t mode, dev_t dev)
{
	printf("Mknod is called:%s\n",path);
	Inode inode;
	int inode_id = get_free_inode();
	if (inode_id == -1) {
		return -ENOSPC;
	}
	init_inode(&inode, REGMODE);
	write_inode_to_disk(inode_id, &inode);
	Directory_entry *entry = (Directory_entry *)malloc(sizeof(Directory_entry));
	entry->inode = inode_id;
	char *file_name = basename(strdup(path));
	strcpy(entry->name, file_name);
	int parent_inode_id = get_parent_inode(path);
	if (parent_inode_id == -1) {
		return -ENOENT;
	}
	if (write_direntry_to_dir(entry, parent_inode_id) == -1) {
		return -ENOSPC;
	}
	free(entry);
	return 0;
}

int fs_mkdir (const char *path, mode_t mode)
{
	printf("Mkdir is called:%s\n",path);
	int inode_id = get_free_inode();
	if (inode_id == -1) {
		return -ENOSPC;
	}
	Inode inode;
	init_inode(&inode, DIRMODE);
	write_inode_to_disk(inode_id, &inode);
	Directory_entry *entry = (Directory_entry *)malloc(sizeof(Directory_entry));
	entry->inode = inode_id;
	char *file_name = basename(strdup(path));
	strcpy(entry->name, file_name);
	int parent_inode_id = get_parent_inode(path);
	if (parent_inode_id == -1) {
		return -ENOENT;
	}
	if (write_direntry_to_dir(entry, parent_inode_id) == -1) {
		return -ENOSPC;
	}
	free(entry);
	return 0;
}

int fs_rmdir (const char *path)
{
	printf("Rmdir is called:%s\n",path);
	int inode_id = get_inode_by_path(path, NULL);
	if (inode_id == -1) {
		return -ENOENT;
	}
	Inode inode = get_inode_by_id(inode_id);
	if (inode.blocks > 1) {
		return -ENOTEMPTY;
	}
	int parent_inode_id = get_parent_inode(path);
	if (parent_inode_id == -1) {
		return -ENOENT;
	}
	Inode parent_inode = get_inode_by_id(parent_inode_id);
	for (int i = 0; i < parent_inode.blocks; i++) {
		Directory dir;
		read_directory_from_disk(parent_inode.direct_pointer[i], &dir);
		for (int j = 0; j < dir.n_count; j++) {
			if (dir.entry[j].inode == inode_id) {
				dir.n_count--;
				for (int k = j; k < dir.n_count; k++) {
					dir.entry[k] = dir.entry[k+1];
				}
				char buffer[BLOCK_SIZE];
				memset(buffer, 0, sizeof(buffer));
				memcpy(buffer, &dir, sizeof(Directory));
				disk_write(parent_inode.direct_pointer[i], buffer);
				delete_inode_from_ibitmap(inode_id);
				return 0;
			}
		}
	}
	return 0;
}

int fs_unlink (const char *path)
{
	printf("Unlink is callded:%s\n",path);
	int inode_id = get_inode_by_path(path, NULL);
	if (inode_id == -1) {
		return -ENOENT;
	}
	Inode inode = get_inode_by_id(inode_id);
	int parent_inode_id = get_parent_inode(path);
	if (parent_inode_id == -1) {
		return -ENOENT;
	}
	Inode parent_inode = get_inode_by_id(parent_inode_id);
	for (int i = 0; i < parent_inode.blocks; i++) {
		Directory dir;
		read_directory_from_disk(parent_inode.direct_pointer[i], &dir);
		for (int j = 0; j < dir.n_count; j++) {
			if (dir.entry[j].inode == inode_id) {
				dir.n_count--;
				for (int k = j; k < dir.n_count; k++) {
					dir.entry[k] = dir.entry[k+1];
				}
				char buffer[BLOCK_SIZE];
				memset(buffer, 0, sizeof(buffer));
				memcpy(buffer, &dir, sizeof(Directory));
				disk_write(parent_inode.direct_pointer[i], buffer);
				delete_inode_from_ibitmap(inode_id);
				return 0;
			}
		}
	}
	return 0;
}

int fs_rename (const char *oldpath, const char *newpath)
{
	printf("Rename is called:%s\n",newpath);
	Inode inode;
	int inode_id = get_inode_by_path(oldpath, &inode);
	char *file_name = basename(strdup(oldpath));
	int parent_inode_id = get_parent_inode(oldpath);
	if (parent_inode_id == -1) {
		return -ENOENT;
	}
	// 从父节点中删除文件
	Inode parent_inode = get_inode_by_id(parent_inode_id);
	parent_inode.mtime = time(NULL);
	parent_inode.ctime = time(NULL);
	if (parent_inode.mode == (REGMODE)) {
		return -ENOTDIR;
	} else {
		for (int i = 0; i < parent_inode.blocks; i++) {
			Directory *dir = (Directory *)malloc(sizeof(Directory));
			read_directory_from_disk(parent_inode.direct_pointer[i], dir);
			int entry_num = dir->n_count;
			for (int j = 0; j < entry_num; j++) {
				if (strcmp(dir->entry[j].name, file_name) == 0) {
					for (j = j + 1; j < entry_num; j++) {
						strcpy(dir->entry[j-1].name, dir->entry[j].name);
						dir->entry[j-1].inode = dir->entry[j].inode;
					}
					break;
				}
			}
			char buffer[BLOCK_SIZE];
			memset(buffer, 0, sizeof(buffer));
			memcpy(buffer, &dir, sizeof(Directory));
			disk_write(parent_inode.direct_pointer[i], buffer);
			if (dir->n_count == 0) {
				delete_data_from_dbitmap(parent_inode.direct_pointer[i]);
			}
			free(dir);
			goto label;
		}
		// 如果在直接指针中没有找到，就继续搜索间接指针
		for (int i = 0; i < 2; i++) {
			int pointers[BLOCK_SIZE];
			read_indirect_pointer(&parent_inode, i, pointers);
			for (int j = 1; j <= pointers[0]; j++) {
				Directory *dir = (Directory *)malloc(sizeof(Directory));
				int entry_num = dir->n_count;
				for (int k = 0; k < entry_num; k++) {
					if (strcmp(dir->entry[k].name, file_name) == 0) {
						delete_inode_from_ibitmap(dir->entry[k].inode);
						for (k = k + 1; k < entry_num; k++) {
							strcpy(dir->entry[k-1].name, dir->entry[k].name);
							dir->entry[k-1].inode = dir->entry[k].inode;
						}
						break;
					}
				}
				char buffer[BLOCK_SIZE];
				memset(buffer, 0, sizeof(buffer));
				memcpy(buffer, &dir, sizeof(Directory));
				disk_write(pointers[j], buffer);
				if (dir->n_count == 0) {
					delete_data_from_dbitmap(pointers[j]);
				}
				free(dir);
				goto label;
			}
		}
	}
label:;
	int new_parent_inode_id = get_parent_inode(newpath);
	if (new_parent_inode_id == -1) {
		return -ENOENT;
	}
	Inode new_parent_inode = get_inode_by_id(new_parent_inode_id);
	Directory_entry entry;
	entry.inode = inode_id;
	strcpy(entry.name, basename(strdup(newpath)));
	if (write_direntry_to_dir(&entry, new_parent_inode_id) == -1) {
		return -ENOSPC;
	}
	return 0;
}


int fs_truncate (const char *path, off_t size)
{
	printf("Truncate is called:%s\n",path);
	Inode *inode = (Inode *)malloc(sizeof(Inode));
	int inode_id = get_inode_by_path(path, inode);
	if (inode_id == -1) {
		return -ENOENT;
	}
	int block_num = inode->blocks;
	int demand_pointer = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
	printf("block_num:%d\n",block_num);
	printf("demand_pointer:%d\n",demand_pointer);
	if (demand_pointer < PNUM && demand_pointer > block_num) {
		for (int i = block_num; i < demand_pointer; i++) {
			inode->direct_pointer[i] = get_free_block();
			if (inode->direct_pointer[i] == -1) {
				return -ENOSPC;
			}
		}
		inode->blocks = demand_pointer;
	} else if (demand_pointer < block_num) {
		inode->blocks = demand_pointer;
	} else {
		if (reconstruct_indirect_pointer(inode, size) == -1) {
			return -ENOSPC;
		}

	}
	inode->size = size;
	inode->mtime = time(NULL);
	inode->ctime = time(NULL);
	write_inode_to_disk(inode_id, inode);
	return 0;
}

int fs_write (const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
	printf("Write is called:%s\n",path);
	// printf("size:%d\n",size);
	// printf("offset:%d\n",offset);
	// if(fs_truncate(path, offset + size + BLOCK_SIZE) != 0) {
	// 	return 0;
	// }
	// Inode *inode = (Inode *)malloc(sizeof(Inode));
	// int inode_id = get_inode_by_path(path, inode);
	// if (inode_id == -1) {
	// 	return -ENOENT;
	// }
	// inode->size = offset + size;
	// inode->mtime = time(NULL);
	// printf("inode_id:%d\n",inode_id);
	// write_inode_to_disk(inode_id, inode);
	// int start_pointer = offset / BLOCK_SIZE;
	// printf("start_pointer:%d\n",start_pointer);
	// int start_num;
	// if (start_pointer < PNUM) {
	// 	start_num = inode->direct_pointer[start_pointer];
		
	// } else {
	// 	start_pointer -= PNUM - 1;
	// 	int pointers[BLOCK_SIZE];
	// 	read_indirect_pointer(inode, 0, pointers);
	// 	start_num = pointers[start_pointer];
	// }
	// char block[BLOCK_SIZE];
	// memset(block, 0, sizeof(block));
	// printf("start_num:%d\n",start_num);
	// disk_read(start_num, block);
	// memcpy(block, buffer, size);
	// block[size + offset % BLOCK_SIZE] = '\0';
	// printf("%s\n", block);	
	// disk_write(start_num, block);
	// // write_file_to_block(inode, start_num, block, size, offset % BLOCK_SIZE);
	// free(inode);
	// return size;
	Inode inode;
	int inode_id = get_inode_by_path(path, &inode);
	if (inode_id == -1) {
		return -ENOENT;
	}
	int start_block_id = offset / BLOCK_SIZE + DATA_BLOCK_POS;
	int end_block_id = (offset + size - 1) / BLOCK_SIZE + DATA_BLOCK_POS;
	int start_offset = offset % BLOCK_SIZE;
	int end_offset = (offset + size - 1) % BLOCK_SIZE;
	int final_size = 0;
	for (int i = start_block_id; i <= end_block_id; i++) {
		if (i == start_block_id && i == end_block_id) {
			final_size += write_file_to_block(&inode, i, buffer, size, start_offset);
		} else if (i == start_block_id) {
			final_size += write_file_to_block(&inode, i, buffer, BLOCK_SIZE - start_offset, start_offset);
		} else if (i == end_block_id) {
			final_size += write_file_to_block(&inode, i, buffer + final_size, end_offset + 1, 0);
		} else {
			final_size += write_file_to_block(&inode, i, buffer + final_size, BLOCK_SIZE, 0);
		}
	}
	inode.size = max(inode.size, offset + size);
	inode.mtime = time(NULL);
	inode.ctime = time(NULL);
	write_inode_to_disk(inode_id, &inode);
	return size;
}


int fs_utime (const char *path, struct utimbuf *buffer)
{
	printf("Utime is called:%s\n",path);
	Inode inode;
	int inode_id = get_inode_by_path(path, &inode);
	inode.atime = buffer->actime;
	inode.mtime = buffer->modtime;
	inode.ctime = time(NULL);
	write_inode_to_disk(inode_id, &inode);
	return 0;
}

int fs_statfs (const char *path, struct statvfs *stat)
{
	printf("Statfs is called:%s\n",path);
	stat->f_bsize = superblock.size;
	stat->f_blocks = BLOCK_NUM;
	stat->f_bfree = superblock.free_block;
	stat->f_bavail = superblock.free_block;
	stat->f_files = MAX_FILE_NUM;
	stat->f_ffree = superblock.free_inode;
	stat->f_favail = superblock.free_inode;
	stat->f_namemax = FILENAME_LEN;
	return 0;
}

int fs_open (const char *path, struct fuse_file_info *fi)
{
	printf("Open is called:%s\n",path);
	return 0;
}

//Functions you don't actually need to modify
int fs_release (const char *path, struct fuse_file_info *fi)
{
	printf("Release is called:%s\n",path);
	return 0;
}

int fs_opendir (const char *path, struct fuse_file_info *fi)
{
	printf("Opendir is called:%s\n",path);
	return 0;
}

int fs_releasedir (const char * path, struct fuse_file_info *fi)
{
	printf("Releasedir is called:%s\n",path);
	return 0;
}

static struct fuse_operations fs_operations = {
	.getattr    = fs_getattr,
	.readdir    = fs_readdir,
	.read       = fs_read,
	.mkdir      = fs_mkdir,
	.rmdir      = fs_rmdir,
	.unlink     = fs_unlink,
	.rename     = fs_rename,
	.truncate   = fs_truncate,
	.utime      = fs_utime,
	.mknod      = fs_mknod,
	.write      = fs_write,
	.statfs     = fs_statfs,
	.open       = fs_open,
	.release    = fs_release,
	.opendir    = fs_opendir,
	.releasedir = fs_releasedir
};

int main(int argc, char *argv[])
{
	if(disk_init())
		{
		printf("Can't open virtual disk!\n");
		return -1;
		}
	if(mkfs())
		{
		printf("Mkfs failed!\n");
		return -2;
		}
    return fuse_main(argc, argv, &fs_operations, NULL);
}
