// This is a simple program which opens/creates a file called data.txt and appends the first 4 arguements  
// It is used in testing for the bouncer


#include <stdio.h>
int main(int argc, char *argv[]) {
    FILE *fp;
    fp  = fopen("data.txt", "a");
    for(int  i = 1 ; i <= 4 ; i++){
        fprintf(fp, argv[i]);
        fputc(' ', fp);
    }
    fputc('\n', fp);
    fclose(fp);
}