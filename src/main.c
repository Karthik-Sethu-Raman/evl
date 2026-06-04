#define FUSE_USE_VERSION 31
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "evl_file.h"
#include "evl_types.h"
#include <fuse.h>
#include <errno.h>

static void usage(void)
{
    fprintf(stderr,
        "Usage:\n"
        "  evl create <file.evl>\n"
        "  evl write  <file.evl> <infile>\n"
        "  evl read   <file.evl>\n"
        "  evl info   <file.evl>\n"
        "  evl verify <file.evl>\n"
        "  evl mount <file.evl> <mountpoint> [-f]\n"
    );
}

static char *prompt_password(const char *prompt)
{
    char *pw = getpass(prompt);
    if (!pw || strlen(pw) == 0) {
        fprintf(stderr, "error: empty password\n");
        return NULL;
    }
    return pw;
}


static const char *VIRTUAL_FILENAME = "/locker.bin";

static evl_file_t *get_evl_ctx(void){ //returning pointer to the mounted EVL container.
    return (evl_file_t *)fuse_get_context()->private_data; //fuse_get_context return pointer to struct fuse_context.
    //fuse_get_context()->private_data is essentially context.private_data of type void *. (generic)
}

static int evl_fuse_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi){
    //*stbuf is the output parameter.
    (void)fi;
    memset(stbuf, 0, sizeof(struct stat)); //setting every byte of stat structure to zero. (preventing garbage)

    if (strcmp(path, "/") == 0) { //0 if equal, asking for root directory.
        stbuf->st_mode  = S_IFDIR | 0755; //S_IFDIR means, this object is a directory. (permissions 0755)
        stbuf->st_nlink = 2; //directory links.
        return 0; // "/" exists!
    }

    if (strcmp(path, VIRTUAL_FILENAME) == 0) { //is linux asking about a virtual file? (current evl filesystem only exposes locker.bin)
        //just one virtual file whose contents map to the encrypted data inside the EVL container.
        evl_file_t *f   = get_evl_ctx(); //getting context from private
        stbuf->st_mode  = S_IFREG | 0644; //regular file with permissions 0644.
        stbuf->st_nlink = 1; //regular gets one link.
        stbuf->st_size  = (off_t)f->header.file_size; //file size
        return 0; //yes, locker.bin exists!
    }

    return -ENOENT; //no such file or directory!
}

static int evl_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags){
    //filler (callback function) manipulates *buf, offfset is ignored for now, fi and flags unused for now.
    (void)offset; (void)fi; (void)flags; //supressing compiler warnings.

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0, 0); //current directory
    filler(buf, "..", NULL, 0, 0); //parent directory
    filler(buf, VIRTUAL_FILENAME + 1, NULL, 0, 0); //"locker.bin" without the leading slash

    /* directory contents become:
        .
        ..
        locker.bin
    */
    return 0; //directory listing completed successfully
}

static int evl_fuse_open(const char *path, struct fuse_file_info *fi){
    //*fi ignored for now.
    (void)fi; //compiler warning supression.
    if (strcmp(path, VIRTUAL_FILENAME) != 0)
        return -ENOENT; //no such file or directory
    return 0; //open allowed.
}

static int evl_fuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
    (void)fi; //unused as before.
    if (strcmp(path, VIRTUAL_FILENAME) != 0) //path validation
        return -ENOENT;

    evl_file_t *f = get_evl_ctx(); //retrieve context.
    //file metadata:
    uint64_t file_size = f->header.file_size;
    uint32_t block_size = f->header.block_size;

    if ((uint64_t)offset >= file_size) //EOF check.
        return 0;

    if ((uint64_t)offset + size > file_size) //truncating oversized reads
        size = file_size - offset;

    size_t total_read = 0; //tracking bytes already read.

    while (total_read < size) { //main loop, keep reading until requested bytes are satisfied.
        uint64_t cur_offset = (uint64_t)offset + total_read; //current file position
        uint64_t block_index = cur_offset / block_size; //determine block
        uint64_t offset_in_blk = cur_offset % block_size; //offset inside the block

        uint8_t  block_buf[EVL_DEFAULT_BLOCK_SIZE]; //temporary storage
        size_t   out_len = 0; //actual bytes in the block after reading

        if (evl_read_block(f, block_index, block_buf, &out_len) != 0){ //evl API
            return -EIO;
        }
        //block_buf contains the actual file data
            

        size_t available = out_len - offset_in_blk; //bytes remaining in this block.
        size_t to_copy   = size - total_read; //how much still needed
        if (to_copy > available) //preventing crossing block boundary, next loop iteration will read another block.
            to_copy = available;

        memcpy(buf + total_read, block_buf + offset_in_blk, to_copy); //actual copy to buf
        total_read += to_copy; //update progress.
    }

    return (int)total_read; //total bytes read
}

static int evl_fuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
    (void)fi;
    if (strcmp(path, VIRTUAL_FILENAME) != 0) //path check.
        return -ENOENT;

    evl_file_t *f = get_evl_ctx(); //get context.
    uint32_t block_size  = f->header.block_size; //block size
    size_t total_written = 0; //total progress

    while (total_written < size) { //keep processing until all requested bytes have been stored.
        uint64_t cur_offset = (uint64_t)offset + total_written;
        uint64_t block_index = cur_offset / block_size;
        uint64_t offset_in_blk = cur_offset % block_size;

        uint8_t block_buf[EVL_DEFAULT_BLOCK_SIZE];
        size_t  out_len = 0; //how much data already exists in this block.
        size_t  to_write = size - total_written;

        if (to_write > block_size - offset_in_blk) //preventing crossing block boundary. Remainder goes into next block during the next loop iteration
            to_write = block_size - offset_in_blk;

        if (offset_in_blk != 0 || to_write < block_size) { //Read-Modify-Write cycle
            int r = evl_read_block(f, block_index, block_buf, &out_len); //read existing block
            if (r != 0)
                memset(block_buf, 0, block_size); //if block doesnt exist, create empty block and fill with 0.
        } else {
            memset(block_buf, 0, block_size); //if we are replacing a block, entire block write, no need to read old contents.
        }

        memcpy(block_buf + offset_in_blk, buf + total_written, to_write); //actual write

        size_t write_len = (offset_in_blk + to_write > out_len) ? offset_in_blk + to_write : out_len; //final length

        if (evl_write_block(f, block_index, block_buf, write_len) != 0){ //encryption.
            return -EIO;
        }
            

        total_written += to_write; //update progress.
    }

    return (int)total_written;
}

static void evl_fuse_destroy(void *private_data){ //cleanup call back which run when the filesystem is being unmounted.
    evl_file_t *f = (evl_file_t *)private_data;
    if (f) { //only cleanup if pointer exists
        evl_file_close(f);
        free(f); //malloc inside cmd_mount
    }
}

//fuse callback table, like the filesystems public API
static const struct fuse_operations evl_oper = {
    .getattr = evl_fuse_getattr,
    .readdir = evl_fuse_readdir,
    .open    = evl_fuse_open,
    .read    = evl_fuse_read,
    .write   = evl_fuse_write,
    .destroy = evl_fuse_destroy,
};


static int cmd_mount(int argc, char *argv[]){
    if (argc < 4) { //4 argument check
        usage();
        return 1;
    }

    const char *evl_path   = argv[2];
    const char *mountpoint = argv[3];

    char *pw = prompt_password("Password: "); //password prompt
    if (!pw) return 1;

    evl_file_t *f = malloc(sizeof(evl_file_t)); //allocate EVL object (heap)
    if (!f) return 1;

    if (evl_file_open(evl_path, pw, f) != 0) { //evl_file.c
        fprintf(stderr, "error: could not open %s (wrong password?)\n", evl_path);
        free(f);
        return 1;
    }

    printf("Mounting %s at %s\n", evl_path, mountpoint);

    //building FUSE arguments
    int fuse_argc    = 2 + (argc - 4);
    char **fuse_argv = malloc(fuse_argc * sizeof(char *)); //new argv array, fuse doesnt want every argument
    if (!fuse_argv) { evl_file_close(f); free(f); return 1; }

    fuse_argv[0] = argv[0];
    fuse_argv[1] = (char *)mountpoint;
    for (int i = 4; i < argc; i++)
        fuse_argv[i - 2] = argv[i];

    int ret = fuse_main(fuse_argc, fuse_argv, &evl_oper, f); //Important part where FUSE learns which functions to implement the filesystem on the mounted EVL object "f".
    free(fuse_argv); //when filesystem unmounted or process terminated..
    return ret; //fuse exit code
}

//EVL file creation:
static int cmd_create(const char *path){
    char *pw = prompt_password("Password: ");
    if (!pw) return 1;

    char *pw2 = getpass("Confirm password: ");
    if (!pw2 || strcmp(pw, pw2) != 0) {
        fprintf(stderr, "error: passwords do not match\n");
        return 1;
    }

    evl_file_t f; //creating evl object, stack
    if (evl_file_create(path, pw, EVL_DEFAULT_BLOCK_SIZE, &f) != 0) { //from evl_file.c
        fprintf(stderr, "error: failed to create %s\n", path);
        return 1;
    }

    //closing the newly created file
    evl_file_close(&f);
    printf("created: %s\n", path);
    return 0;
}

static int cmd_write(const char *evl_path, const char *in_path){
    char *pw = prompt_password("Password: ");
    if (!pw) return 1;

    evl_file_t f;//on stack instead of heap, heap not required!
    if (evl_file_open(evl_path, pw, &f) != 0) { //from evl_file.c
        fprintf(stderr, "error: could not open %s (wrong password?)\n", evl_path);
        return 1;
    }

    int infd = open(in_path, O_RDONLY); //returns the fd number
    if (infd < 0) {
        fprintf(stderr, "error: could not open input file %s\n", in_path);
        evl_file_close(&f);
        return 1;
    }

    uint8_t buf[EVL_DEFAULT_BLOCK_SIZE];
    uint64_t block_index = 0;
    ssize_t bytes_read;
    int ret = 0;

    while ((bytes_read = read(infd, buf, sizeof(buf))) > 0) {
        if (evl_write_block(&f, block_index, buf, (size_t)bytes_read) != 0) { //from evl_file.c
            fprintf(stderr, "error: write failed at block %llu\n", //error condition, loop breaks.
                    (unsigned long long)block_index);
            ret = 1;
            break;
        }
        block_index++; //increment block
    }

    if (bytes_read < 0) {
        fprintf(stderr, "error: read error on input file\n");
        ret = 1;
    }

    //cleanup and close
    close(infd);
    evl_file_close(&f);

    //success.
    if (ret == 0)
        fprintf(stderr, "wrote %llu block(s) to %s\n",
                (unsigned long long)block_index, evl_path);
    return ret;
}

//read operation, similar
static int cmd_read(const char *evl_path){
    char *pw = prompt_password("Password: ");
    if (!pw) return 1;

    evl_file_t f;
    if (evl_file_open(evl_path, pw, &f) != 0) {
        fprintf(stderr, "error: could not open %s (wrong password?)\n", evl_path);
        return 1;
    }

    uint8_t buf[EVL_DEFAULT_BLOCK_SIZE];
    uint64_t block_index = 0;
    size_t out_len = 0;
    int ret = 0;

    while (evl_read_block(&f, block_index, buf, &out_len) == 0) {
        if (write(STDOUT_FILENO, buf, out_len) != (ssize_t)out_len) {
            fprintf(stderr, "error: write to stdout failed\n");
            ret = 1;
            break;
        }
        block_index++;
    }

    evl_file_close(&f);
    return ret;
}

//EVL file info
static int cmd_info(const char *evl_path){
    char *pw = prompt_password("Password: "); //required as we have to authenticate header.
    if (!pw) return 1;

    evl_file_t f;
    if (evl_file_open(evl_path, pw, &f) != 0) { //from evl_file.c
        fprintf(stderr, "error: could not open %s (wrong password?)\n", evl_path);
        return 1;
    }

    printf("file:         %s\n",   evl_path);
    printf("format:       EVL v%u\n", f.header.format_version);
    printf("block_size:   %u bytes\n", f.header.block_size);
    printf("file_size:    %llu bytes\n", (unsigned long long)f.header.file_size);

    printf("file_id:      ");
    for (int i = 0; i < EVL_FILE_ID_SIZE; i++)
        printf("%02x", f.header.file_id[i]);
    printf("\n");

    evl_file_close(&f);
    return 0;
}

//verification using password to check tampering.
static int cmd_verify(const char *evl_path){
    char *pw = prompt_password("Password: ");
    if (!pw) return 1;

    evl_file_t f;
    if (evl_file_open(evl_path, pw, &f) != 0) {
        fprintf(stderr, "FAIL: %s (wrong password or tampered header)\n", evl_path);
        return 1;
    }

    printf("OK: %s authenticates correctly\n", evl_path);
    evl_file_close(&f);
    return 0;
}


//entry point:
int main(int argc, char *argv[]){
    if (argc < 3) {
        usage();
        return 1;
    }

    const char *cmd  = argv[1];
    const char *path = argv[2];

    if (strcmp(cmd, "create") == 0 && argc == 3)
        return cmd_create(path);

    if (strcmp(cmd, "write") == 0 && argc == 4)
        return cmd_write(path, argv[3]);

    if (strcmp(cmd, "read") == 0 && argc == 3)
        return cmd_read(path);

    if (strcmp(cmd, "info") == 0 && argc == 3)
        return cmd_info(path);

    if (strcmp(cmd, "verify") == 0 && argc == 3)
        return cmd_verify(path);

    if (strcmp(cmd, "mount")==0 && argc >=4)
        return cmd_mount(argc, argv);

    usage();
    return 1;
}