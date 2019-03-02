/* Author: Enock Gansou*/

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <wordexp.h>
#include <sys/wait.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>


#define OUT    0
#define IN    1

int timestamp;
int time_len;
char *token;
char *employee;
char *guest;

/* 1 for enter, 0 for leave */
int enter_leave = 0;
int enter_leave_len = 1;

int room = -1;
int room_len = 1;
char *batch_file;
char *logpath;

/* Assigning the iv, we might change it */
char iv[16] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"; 
char tag[20] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";


/* Generate a randon string */
void gen_random(char *s) {
    static const char alphanum[] =  "abcdefghijklmnopqrstuvwxyz";
    int len;
    int i;
    /* Generate  */
    len = 12;

    for (i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }   
}

/* Count the number of words in a string */
unsigned countWords(char *str)
{
    int state = OUT;
    unsigned wc = 0;  // word count
 
    // Scan all characters one by one
    while (*str)
    {
        // If next character is a separator, set the 
        // state as OUT
        if (*str == ' ' || *str == '\n' || *str == '\t')
            state = OUT;
 
        // If next character is not a word separator and 
        // state is OUT, then set the state as IN and 
        // increment word count
        else if (state == OUT)
        {
            state = IN;
            ++wc;
        }
 
        // Move to next character
        ++str;
    }
 
    return wc;
}

int is_alphanumeric (char *s) {
    int i;
    int len;

    if (s == NULL) return 0;

    len = strlen(s);

    for(i = 0; i < len; i++){
        if(!isalnum(s[i])) return 0;
    }

    return 1;
}


int is_alphabetic (char *s) {
    int i;
    int len;

    if (s == NULL) return 0;

    len = strlen(s);

    for(i = 0; i < len; i++){
        if(!isalpha(s[i])) return 0;
    }

    return 1;
}

int is_digit (char *s) {
    int i;
    int len;

    if (s == NULL) return 0;

    len = strlen(s);

    for(i = 0; i < len; i++){
        if(!isdigit(s[i])) return 0;
    }

    return 1;
}

int is_valid_name (char *s) {
    int i;
    int len;

    if (s == NULL) return 0;

    len = strlen(s);

    for(i = 0; i < len; i++){
        if(!isalnum(s[i]) && s[i] != '_' && s[i] != '.' && s[i] != '/') return 0;
    }

    return 1;
}

void  execute(char **argv)
{
     pid_t  pid;
     int    status;

     if ((pid = fork()) < 0) {     /* fork a child process           */
          exit(1);
     }
     else if (pid == 0) {          /* for the child process:         */
          if (execvp(*argv, argv) < 0) {     /* execute the command  */
               exit(1);
          }
     }
     else {                                  /* for the parent:      */
          while (wait(&status) != pid)       /* wait for completion  */
               ;
     }
}


int parse_cmdline(int argc, char *argv[]) {

    int opt = -1;
    int is_good = -1;


 /* check for used values */
    int time_flag = 0, token_flag = 0, employee_flag = 0, guest_flag = 0,
    enter_leave_flag_A = 0, enter_leave_flag_L = 0, room_flag = 0, batch_flag = 0;

//pick up the switches
    while ((opt = getopt(argc, argv, "T:K:E:G:ALR:B:")) != -1) {
        switch(opt) {
            case 'B':
        //batch file
                batch_file = optarg;
                batch_flag += 1;
            break;

            case 'T':
        //timestamp
            if(is_digit(optarg)){
                timestamp = atoi(optarg);
                if ( timestamp < 1 || timestamp > 1073741823) {
                    printf("invalid");
                    exit(255);
                }
                else {
                    time_len = strlen(optarg);
                    time_flag += 1;
                }
            }
            else {
                printf("invalid");
                exit(255);  
            }
            break;

            case 'K':
    //secret token
            token = optarg;
            if (is_alphanumeric(token)){
                token_flag += 1;
            }
            else {
                printf("invalid");
                exit(255);  
            }
            break;

            case 'A':
    //arrival
            if(enter_leave_flag_L == 0){
                enter_leave = 1;
                enter_leave_flag_A += 1;
            }
            else {
                printf("invalid");
                exit(255);  
            }
            break;

            case 'L':
    //departure
            if(enter_leave_flag_A == 0){
                enter_leave = 0;
                enter_leave_flag_L += 1;
            }
            else {
                printf("invalid");
                exit(255);  
            }       
            break;

            case 'E':
    //employee name
            employee = optarg;
            if (is_alphabetic(employee) && guest_flag == 0){
                employee_flag += 1;
            }
            else {
                printf("invalid");
                exit(255);  
            }
            break;

            case 'G':
    //guest name
            guest = optarg;
            if (is_alphabetic(guest) && employee_flag == 0){
                guest_flag += 1;
            }
            else {
                printf("invalid");
                exit(255);  
            }
            break;

            case 'R':
    //room ID
            if(is_digit(optarg)){
                room = atoi(optarg);
                if ( room < 0 || room > 1073741823) {
                    printf("invalid");
                    exit(255);
                }
                else {
                    room_len = strlen(optarg);
                    room_flag += 1;
                }
            }
            else {
                printf("invalid");
                exit(255);  
            }
            break;

            case '?':
                printf("invalid");
                exit(255); 
            break; 

            default:
    //unknown option, leave
                printf("invalid");
                exit(255);
            break;
        }

    }


    if(time_flag && token_flag && (enter_leave_flag_A || enter_leave_flag_L) && (employee_flag || guest_flag) && !room_flag && !batch_flag){
        int total = 1 + 2 * time_flag + 2 * token_flag + enter_leave_flag_A + enter_leave_flag_L + 2 * employee_flag + 2 * guest_flag + 1;
        if (argc != total){
            printf("invalid");
            exit(255);
        } 
    }
    else if(time_flag && token_flag && (enter_leave_flag_A || enter_leave_flag_L) && (employee_flag || guest_flag) && room_flag && !batch_flag){
        int total = 1 + 2 * time_flag + 2 * token_flag + enter_leave_flag_A  + enter_leave_flag_L + 2 * employee_flag + 2 * guest_flag + 2 * room_flag + 1;
        if (argc != total){
            printf("invalid");
            exit(255);
        } 
    }
    else if (batch_flag){
        int total = 1 + 2 * batch_flag;

        FILE *file = fopen(batch_file, "r");

        if (total == argc && file != NULL) {

            char *line = NULL;
            size_t len_ = 0;
            ssize_t read;
            int len = 0;
            char **arg = NULL;
            int i;

            while ((read = getline(&line, &len_, file)) != -1) {
                i = 0;

                /* printf("%s", line); */

                if(line[strlen(line)-1] == '\n') line[strlen(line)-1] = 0;

                len = countWords(line);  

                arg = malloc((len + 2) * sizeof(char *));
                
                for(i = 1; i < len + 1; i++) {
                    arg[i] = malloc(strlen(line) * sizeof(char));
                    memset(arg[i], 0x00, strlen(line) * sizeof(char));
                }

                arg[0] = malloc(15);
                memset(arg[0], 0x00, 15);
                strcat(arg[0], "./logappend");

                char *p = strtok(line," ");

                i = 1;
                while (p != NULL){
                    strcat(arg[i],p);
                    p = strtok(NULL, " ");
                    i++;
                }

                arg[i] = NULL;

                /* We execute the command line here */
                execute(arg);


                /* printf("%s\n", arg[5]); */

                for(i = 0; i < len + 2; i++) {
                    free(arg[i]);
                }

                
                free(arg);
            }

            fclose(file);
            exit(0);
        }

        else {
            printf("invalid");
            exit(255);
        }         
    }
    else {
        printf("invalid");
        exit(255);
    }



//pick up the positional argument for log path
    if(optind < argc) {
        logpath = argv[optind];
        if(!is_valid_name(logpath)){
            printf("invalid");
            exit(255);
        }

    }


    return is_good;
}


int encrypt(unsigned char *plaintext, FILE *out, unsigned char *key, 
    unsigned char *iv, unsigned char *tag)
{
 /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1025], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();

    memset(inbuf, '\0', 1025); 


/* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) return 0;


    for (;;) {
        strncpy((char *)inbuf, (char *)plaintext, 1024);
        inlen = strlen((char *)inbuf);
        plaintext = plaintext + inlen;

     /*inlen = fread(inbuf, 1, 1024, in); */
        if (inlen <= 0)
         break;
     if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
         /* Error */
         EVP_CIPHER_CTX_free(ctx);
         return 0;
     }
     fwrite(outbuf, 1, outlen, out);
     memset(inbuf, '\0', 1025); 
 }

 if (!EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) { 
     /* Error */
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
fwrite(outbuf, 1, outlen, out);

 /* Get the tag */
if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) return 0;

/* add the tag first after the encrypted file */
fwrite(tag, 1, 16, out);

/* Then, add the random iv */
fwrite(iv, 1, 12, out);

EVP_CIPHER_CTX_free(ctx);
return 1;
}


int decrypt(FILE* in,  unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char * tag)
{

/* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();

    int ret;

    char *ptr = (char *)plaintext;

/* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) return -1;

/* Provide the message to be decrypted, and obtain the plaintext output.
 * EVP_DecryptUpdate can be called multiple times if necessary
 */

    for (;;) {
        inlen = fread(inbuf, 1, 1024, in);
        if (inlen <= 0)
         break;
     if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
         /* Error */
         EVP_CIPHER_CTX_free(ctx);
         return 0;
     }

     /* fwrite(outbuf, 1, outlen, out); */
     strncpy(ptr, (char *)outbuf, outlen);
     ptr += outlen;
 }

/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
 if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) return -1;

/* Finalise the decryption. A positive return value indicates success,
 * anything else is a failure - the plaintext is not trustworthy.
 */
 ret = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);

/* Clean up */
 EVP_CIPHER_CTX_free(ctx);

 if(ret > 0)
 {
    /* Success */
    strncpy(ptr, (char *)outbuf, outlen);
    return 1;
}
else
{
    /* Verify failed */
    return -1;
}


}

char * generate_key(){

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    char hex_value[3]; 

    int i = 0;
    int len = 0;

    /* initialize the key */
    char *key = malloc(33); 
    memset(key, 0x00, 33);
    
    
    /* Allocate enough space for the retrieved input token and some salt (Dictionaty Attack Prevention) */
    len = strlen(token) + 20;
    char * temp = malloc(len);
    memset(temp, 0x00, len);


    strcat(temp, token);
    strcat(temp, "%@#&4(Q@1&7#84A"); //Adding salt here 

    OpenSSL_add_all_digests();
   
    md = EVP_get_digestbyname("sha256");

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, temp, strlen(temp));
    EVP_DigestFinal(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);
    free(temp);
    
    for (i = 0; i < 16; i++){
        sprintf(hex_value, "%02x", md_value[i]);
        strcat(key, hex_value);
     }

     return key;

}


char *process_all_info () {
    char *process;
    int len = 0; 
    if(employee){
        len = strlen(employee) + enter_leave_len + room_len + time_len + 30;
        process = malloc(len);
        memset(process, '\0', len); 
        sprintf(process, "E %s %dR%dT%d",
            employee, enter_leave, room, timestamp);
    }
    else if(guest){
        len += strlen(guest) + enter_leave_len + room_len + time_len + 30;
        process = malloc(len);
        memset(process, '\0', len); 
        sprintf(process,"G %s %dR%dT%d",
            guest, enter_leave, room, timestamp);
    }
    return process;
}

char *process_part_info () {
    char *process;
    int len = 0;
    len = enter_leave_len + room_len + time_len + 30;
    process = malloc(len);
    memset(process, '\0', len); 
    sprintf(process, ";%dR%dT%d", enter_leave, room, timestamp);
    return process;
}



void process_data (char *decrypted) {

    char * line;
    FILE * file;
    char *key; 
    char *rest = decrypted;
    int new_len = 0; 

    /* Allocate enough space for both the origina text and the new information */
    if(employee) new_len = strlen(decrypted) + strlen(employee) + enter_leave_len + room_len + time_len + 100; 
    else if (guest) new_len = strlen(decrypted) + strlen(guest) + enter_leave_len + room_len + time_len + 100;

    char *new_string = malloc (new_len);
    memset(new_string, 0x00, new_len);
    int processed = 0;


    while ((line = strtok_r(rest, "\n", &rest))) {

        /* Allocate space for the type, the individual and his or her history */
        char type[3] ="\0\0\0" ;
        int len = strlen(line) + 1;
        char *person = malloc(len);
        char *history = malloc(len);
        
        memset(person, 0x00, len);
        memset(history, 0x00, len); 

        /* copy the line being processed to the new string */
        strcat(new_string, line);
        
        /* Get the data at the current line */    
        sscanf(line,"%s %s %s", type, person, history);
        
        /* process the matcing employee or guest*/
        if((*type == 'E' && employee != NULL && strcmp(person,employee) == 0) || (*type == 'G' && guest != NULL && strcmp(person,guest) == 0)) {

            /* the enter_leave, the room, and the timestamp */
            int e_l, r, t;
            char *info;

            /*process the remaining of the line */
            char *new_info = process_part_info();

            /* the content is being processed */
            processed = 1; 


            /* Get the most recent information */
            char *p = strtok(history, ";");
            while (p != NULL){
                info = p;
                p =  strtok(NULL, ";");
            }

            /* get all the current states */
            sscanf(info,"%dR%dT%d", &e_l, &r, &t);

            /* Add new information if it is valid */

            /* if you leave a room */
            if (e_l == 0 && r >= 0 && t < timestamp){
                /* You can enter a room or leave the building */
                if ((enter_leave == 1 && room >= 0) || (enter_leave == 0 && room == -1)){
                    strcat(new_string, new_info);
                }
                else {
                    printf("invalid");
                    exit(255);
                }
            }

            /* if you leave the building */
            else if (e_l == 0 && r == -1 && t < timestamp){
                /* You can enter the building */
                if (enter_leave == 1 && room == -1){
                    strcat(new_string, new_info);
                }
                else {
                    printf("invalid");
                    exit(255);
                }
            }

            /* if you enter a room */
            else if (e_l == 1 && r >= 0 && t < timestamp){
                /* You can leave the room*/
                if (enter_leave == 0 && room == r) {
                    strcat(new_string, new_info);
                }
                
                else {
                    printf("invalid");
                    exit(255);
                }
            }

            /* if you enter the building */
            else if (e_l == 1 && r == -1 && t < timestamp){
                /* You can leave the building or you can enter a room */
                if ((enter_leave == 0 && room == -1) || (enter_leave == 1 && room >= 0)){
                    strcat(new_string, new_info);
                }
                else {
                    printf("invalid");
                    exit(255);
                }
            }

            else {
                printf("invalid");
                exit(255);
            }

            free(new_info);
                 
        }

        strcat(new_string, "\n");

        free(person);
        free(history);

    }    

    /* if an update has not been made */
    if(!processed) {
        if(enter_leave == 1 && room == -1){
            char * new_user = process_all_info();
            strcat(new_string, new_user);
            strcat(new_string, "\n");
            free(new_user);
        }
        else{
            printf("invalid");
            exit(255);
        }
    }
    

    file = fopen(logpath, "w");
    if (file == NULL){
        printf("invalid");
        exit(255);
    }

    /* Generate random IV */
    gen_random((char *)iv);
    key = generate_key();

    encrypt ((unsigned char *) new_string, file, (unsigned char *) key, (unsigned char *) iv, (unsigned char *) tag);

    /************************************* Uncomment those lines to see what the output looks like *****************************************/
    /*printf("Random IV generated: %s\n", iv);
    printf("Key generated: %s\n", key);
    printf("Current file state:\n");
    printf("%s", new_string);*/

    fclose(file);
    free(key);
    free(new_string);
}



int main(int argc, char *argv[]) {
    
    char *key; 

    FILE *file;

    int status;

    parse_cmdline(argc, argv); 

    srand(time(NULL));

    
    key = generate_key();


  /* open the log file */
    file = fopen(logpath, "r");
    status = 0;
    if (file == NULL){
        file = fopen(logpath, "w");
        status = 1;
        if (file == NULL){
            printf("invalid");
            exit(255);
        } 
    } 


 /* status 1: create the file and append data to it*/
    if (status == 1) {
        if(enter_leave == 1 && room == -1){
            char *process0 = process_all_info();
            int len = strlen(process0) + 10; 
            char *process1 = malloc(len);
            memset(process1, '\0', len); 
            strcat(process1, process0);
            strcat(process1,"\n");


            /* Generate random IV */
            gen_random((char *)iv);

            encrypt ((unsigned char *) process1, file, (unsigned char *) key, (unsigned char *) iv, (unsigned char *) tag);

            free(key);
            free(process1);
            fclose(file);
        }
        else{
            printf("invalid");
            remove(logpath);
            exit(255);
        }
    }

/* status 0: file has alreaddy been created. Now, retrieve data from the file and process it */
    else{

    /* Declare variables */
        unsigned char *decryptedtext;
        int final;
        unsigned char tag[20];
        FILE * file2;
        char c;
        int i = 0;
        int len = 0;

    /* Set the tag to all zeros */
        memset(tag, '\0', 20); 

    /* Find the size of the file */
        fseek(file, 0, SEEK_END);
        len = ftell(file);


    /* Allocate enough space for the file decryption */
        decryptedtext = (unsigned char *) malloc(len + 1);
        memset(decryptedtext, '\0', len + 1);

    /* Get the tag and the IV from the end of my file*/
        fseek(file, 0, SEEK_SET);
        fseek(file, -28, SEEK_END); 
        fread(tag, 16, 1,file);
        fread(iv, 12, 1,file);


    /* Get the content of the file without the tag to be copied to another file*/
        fseek(file, 0, SEEK_SET); 

        file2 = fopen("cipher.txt", "w");
        if (file2 == NULL){
            printf("invalid"); 
            exit(255);
        }
        c = fgetc(file);
        while (i < len - 28) {
            fputc(c, file2);
            c = fgetc(file);
            i++;
        }
        fclose(file2);
        fclose(file);

    /* Decrypt the contents of the file to the decrypted text string */
        file2 = fopen("cipher.txt", "r");
        final = decrypt (file2,  decryptedtext, (unsigned char *) key, (unsigned char *) iv, tag);
        free(key);
        fclose(file2);

    /* At this point, we can delete the extra file we created */
        remove("cipher.txt");

    /* Make sure of the integrity of the file by using the tag*/
        if (final == -1) {
            printf("invalid");
            exit(255);
        }
        else {
        /* More work here */      
            process_data((char *) decryptedtext);  
        }

        free(decryptedtext);

    }
    
    return 0;
}


