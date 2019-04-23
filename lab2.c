#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

static char* prog_name;

#define BUFF_SIZE 1024*1024                                                                                                                                                                                                                                     

typedef struct {
    char *path;
    char filename[NAME_MAX];
    off_t file_size;
} Fileinfo;

int cmp_filename(const void *fst, const void *snd)
{
    return strcmp( ((Fileinfo*)fst)->filename, ((Fileinfo*)snd)->filename );
}

int cmp_size(const void *fst, const void *snd)
{
    return ((Fileinfo*)fst)->file_size > ((Fileinfo*)snd)->file_size;
}

char* basename(char *filename)
{
    char *p = strrchr(filename, '/');
    return p ? p + 1 : filename;
}

void walk_dir(const char *src_dir, Fileinfo **files, int *files_count)
{
    DIR *curr = opendir(src_dir);
    if (!curr) {
        fprintf(stderr, "%s Cannot open dir: %s, %s \n",prog_name, src_dir, strerror(errno));
        return;
    }
    struct dirent *info;
    char *full_path = (char*)malloc(strlen(src_dir) + strlen(info->d_name) + 1); 
    if (!full_path) {
        fprintf(stderr, "%s Cannon alloc memory for dir: %s \n", prog_name, src_dir);
        return;
    }
    if (!realpath(src_dir, full_path)) {  
        fprintf(stderr, "%s Cannot get full path of file: %s, %s \n", prog_name, src_dir, strerror(errno));
        free(full_path);
        closedir(curr);
        return;
    }
    strcat(full_path, "/");
    int base_dir_len = strlen(full_path);  
    while ((info = readdir(curr))) {
        full_path[base_dir_len] = 0;
        strcat(full_path, info->d_name);
        if (info->d_type == DT_DIR && strcmp(info->d_name, ".") && strcmp(info->d_name, "..")) {
            walk_dir(full_path, files, files_count);
        }
        if (info->d_type == DT_REG) {
            struct stat file_stat;
            if (stat(full_path, &file_stat) == -1) {
                fprintf(stderr, "%s Cannot get stat's from file: %s, %s \n", prog_name, full_path, strerror(errno));
                continue;
            }
            Fileinfo* old_files = *files;
            *files = (Fileinfo*)realloc(*files, ++(*files_count) * sizeof (Fileinfo));
            if (!*files) {
                fprintf(stderr, "%s Cannot alloc memory for file %s \n", prog_name, full_path);
                *files = old_files;
                --(*files_count);
                continue;
            }
            Fileinfo *files_arr = *files;
            int pos = *files_count - 1;
            files_arr[pos].path = full_path;
            strcpy(files_arr[pos].filename, info->d_name);
            files_arr[pos].file_size = file_stat.st_size;
        }
    }
    free(full_path);
    closedir(curr);
}

void write_files(Fileinfo *files, size_t files_count, const char* out_dir)
{
    char *out_path = NULL;
    if (!(out_path = realpath(out_dir, NULL))) {
        fprintf(stderr, "%s Cannot get full path of file: %s, %s \n", prog_name, out_dir, strerror(errno));
        return;
    }
    strcat(out_path, "/");
    int out_path_len = strlen(out_path);
    for (int i = 0; i < files_count; ++i) {
        char *out_name = malloc(strlen(out_path) + 1 + strlen(files[i].filename));
        strcat(out_name, "/");
        strcat(out_name, files[i].filename);
        out_name[out_path_len] = 0;
        while (access(out_name, F_OK) != -1) {
                strcat(out_name, "_");
        }
        FILE *in = fopen(files[i].path, "r");
        if (!in) {
            fprintf(stderr, "%s Cannot open for read file: %s, %s \n", prog_name, files[i].path, strerror(errno));
            continue;
        }
        FILE *out = fopen(out_name, "w+");
        if (!out) {
            fprintf(stderr, "%s Cannot open for write file: %s, %s \n", prog_name, out_name, strerror(errno));
            fclose(in);
            continue;
        }
        char buff[BUFF_SIZE];
        int bytes_read;
        while ((bytes_read = fread(buff, 1, BUFF_SIZE, in))) {
            if (fwrite(buff, 1, bytes_read, out) != bytes_read) {
                fprintf(stderr, "%s Error writing file %s, %s \n", prog_name, out_name, strerror(errno));
            }
        }
        fclose(in);
        fclose(out);
        fflush(out);

        free(out_name);
    } 
}

int main(int argc, char *argv[])
{
    prog_name = basename(argv[0]);
    if (argc != 4) {
        fprintf(stderr, "%s Program need 3 arguments \n", prog_name);
        return 1;
    }
    char *src_dir = argv[1];
    int mode = atoi(argv[2]);
    if (mode != 1 && mode != 2) {
        fprintf(stderr, "%s Correct mode: 1 (by size) and 2 (by filename) \n", prog_name);
        return 1;
    }
    char *dest_dir = argv[3];
    Fileinfo *files = NULL;
    int files_count = 0;  
    walk_dir(src_dir, &files, &files_count);
    qsort(files, files_count, sizeof (*files), mode == 1 ? cmp_size : cmp_filename);
    write_files(files, files_count, dest_dir);
    for (int i = 0; i < files_count; i++)
        free(files[i].path);
    free(files);
    return 0;
}