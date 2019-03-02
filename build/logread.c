/* Author: Kevin Wittner */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define OPT_STRING "K:PSRE:G:VTI"
#define ERROR_CODE 255
#define MAX_ROOM_ID 1073741823
#define GALLERY_ID -1
#define TAG_LEN 16
#define IV_LEN 12

struct person_node {
	char *name;
	char person_type;
	struct person_node *next;
};

struct room_node {
	unsigned long room_id;
	struct person_node *people_list;
	struct room_node *next;
};

struct person_node *add_to_person_list(struct person_node *head, char *name, char person_type) {
	struct person_node *new_node = malloc(sizeof(struct person_node));
	new_node->name = name;
	new_node->person_type = person_type;
	new_node->next = NULL;

	if (head == NULL || strcmp(name, head->name) < 0) {
		new_node->next = head;
		return new_node;
	}

	struct person_node *current = head;
	while (current->next != NULL && strcmp(name, current->next->name) > 0) {
		current = current->next;
	}

	new_node->next = current->next;
	current->next = new_node;

	return head;
}

void print_person_list(struct person_node *head) {
	struct person_node *current = head;
	while (current != NULL) {
		if (current != head) {
			putchar(',');
		}
		printf("%s", current->name);
		current = current->next;
	}
	putchar('\n');
}

int person_list_contains(struct person_node *head, char *name, char person_type) {
	while (head != NULL) {
		if (head->person_type == person_type && strcmp(head->name, name) == 0) {
			return 1;
		} else {
			head = head->next;
		}
	}

	return 0;
}

struct room_node *create_room_node(long room_id, char *name, char person_type, struct room_node *next) {
	struct room_node *new_node = malloc(sizeof(struct room_node));
	new_node->room_id = room_id;
	new_node->people_list = NULL;
	new_node->next = next;

	if (name != NULL) {
		new_node->people_list = add_to_person_list(new_node->people_list, name, person_type);
	}

	return new_node;
}

struct room_node *add_to_room_list(struct room_node *head, long room_id, char *name, char person_type) {
	if (head == NULL || room_id < head->room_id) {
		return create_room_node(room_id, name, person_type, head);
	}

	struct room_node *current = head;
	while (current->next != NULL && room_id > current->next->room_id) {
		current = current->next;
	}

	if (current != NULL && current->room_id == room_id) {
		current->people_list = add_to_person_list(current->people_list, name, person_type);
	} else if (current->next != NULL && current->next->room_id == room_id) {
		current->next->people_list = add_to_person_list(current->next->people_list, name, person_type);
	} else {
		struct room_node *new_node = create_room_node(room_id, name, person_type, current->next);
		current->next = new_node;
	}

	return head;
}

int get_current_line_length(char *line) {
	int line_length = 0;
	while (line[line_length] != '\n' && line[line_length] != '\0') {
		line_length++;
	}

	return line_length;
}

int decrypt(FILE* in, unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *tag) {
	// Allow enough space in output buffer for additional block
    unsigned char inbuf[1024], outbuf[1025 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen, ret;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    char *ptr = (char *)plaintext;

	// Initialise the decryption operation
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
    	return -1;
    }

	// Provide the message to be decrypted, and obtain the plaintext output.
    while ((inlen = fread(inbuf, 1, 1024, in)) > 0) {
     	if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
         	EVP_CIPHER_CTX_free(ctx);
         	return -1;
     	}

     	strncpy(ptr, (char *)outbuf, outlen);
     	ptr += outlen;
 	}

	// Set expected tag value. Works in OpenSSL 1.0.1d and later
 	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)) {
 		return -1;
 	}

	// Finalise the decryption. A positive return value indicates success, anything else is a failure - the plaintext is not trustworthy
 	ret = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);

	// Clean up
 	EVP_CIPHER_CTX_free(ctx);

 	if(ret > 0) {
	    strncpy(ptr, (char *)outbuf, outlen);
	    return 1;
	} else {
    	return -1;
	}
}


unsigned char *decrypt_file(FILE *log_file, unsigned char *key) {
    unsigned char *decrypted_text, tag[TAG_LEN], iv[IV_LEN];
    int final = 0, i = 0, len = 0;
    FILE *temp_file;
    char c;

    // Find the size of the file
    fseek(log_file, 0, SEEK_END);
    len = ftell(log_file);
    fseek(log_file, 0, SEEK_SET);

    // Allocate enough space for the file decryption
    decrypted_text = (unsigned char *)malloc(len + 1);

    // Get the tag and the IV from the end of my file
    fseek(log_file, -28, SEEK_END); 
    fread(tag, TAG_LEN, sizeof(unsigned char), log_file);
    fread(iv, IV_LEN, sizeof(unsigned char), log_file);
    fseek(log_file, 0, SEEK_SET);

    // Get the content of the file without the tag to be copied to another file
    temp_file = fopen("cipher.txt", "w");
    if (temp_file == NULL){
        printf("invalid");
        exit(255);
    }
    c = fgetc(log_file);
    while (i < len - 28) {
        fputc(c, temp_file);
        c = fgetc(log_file);
        i++;
    }
    fclose(temp_file);
    fclose(log_file);

    // Decrypt the contents of the file to the decrypted text string
    temp_file = fopen("cipher.txt", "r");
    final = decrypt(temp_file, decrypted_text, key, iv, tag);
    free(key);
    fclose(temp_file);

    // At this point, we can delete the extra file we created
    remove("cipher.txt");

    // Make sure of the integrity of the file by using the tag
    if (final == -1) {
        printf("invalid");
        exit(255);
    }

    return decrypted_text;
}

unsigned char *generate_key(char *original_key){

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
    len = strlen(original_key) + 20;
    char * temp = malloc(len);
    memset(temp, 0x00, len);


    strcat(temp, original_key);
    strcat(temp, "%@#&4(Q@1&7#84A"); //Addind salt here 

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

     return (unsigned char *)key;

}

void print_current_state(char *log) {
	int line_length;
	struct person_node *employee_list = NULL, *guest_list = NULL;
	struct room_node *room_list = NULL;

	char *line = log;
	while ((line_length = get_current_line_length(line)) > 0) {
		if (line[0] == 'E' || line[0] == 'G') {
			line[line_length] = '\0';
			char *last_entry = strrchr(line, ';');
			if (last_entry == NULL) {
				last_entry = strrchr(line, ' ');
			}
			last_entry = last_entry + 1;

			int enter_or_leave;
			long room_id;
			unsigned long time;
			sscanf(last_entry, "%dR%ldT%lu", &enter_or_leave, &room_id, &time);

			int left_gallery = enter_or_leave == 0 && room_id == GALLERY_ID;
			if (!left_gallery) {
				unsigned long name_length = 0;
				int i;
				for (i = 2; line[i] != ' '; i++) {
					name_length++;
				}
				char *name = malloc(name_length + 1);
				strncpy(name, &line[2], name_length);
				name[name_length] = '\0';

				if (line[0] == 'G') {
					guest_list = add_to_person_list(guest_list, name, 'G');
				} else {
					employee_list = add_to_person_list(employee_list, name, 'E');
				}

				if (enter_or_leave == 1 && room_id != GALLERY_ID) {
					room_list = add_to_room_list(room_list, room_id, name, line[0]);
				}
			}	
		} else {
			printf("integrity violation\n");
			exit(ERROR_CODE);
		}

		line = line + line_length + 1;
	}

	print_person_list(employee_list);
	print_person_list(guest_list);

	struct room_node *current_room = room_list;
	while (current_room != NULL) {
		printf("%ld: ", current_room->room_id);
		print_person_list(current_room->people_list);
		current_room = current_room->next;
	}
}

void print_rooms_entered(char *log, char *name, char person_type) {
	int line_length;

	char *line = log;
	while ((line_length = get_current_line_length(line)) > 0) {
		if (line[0] == person_type && strncmp(name, &line[2], strlen(name)) == 0) {
			char *curr_entry = strchr(line, ';');
			if (curr_entry == NULL) {
				return;
			} else {
				curr_entry = curr_entry + 1;
			}

			int found_entry = 0;
			while (curr_entry != NULL && curr_entry - line < line_length) {
				char *next_entry = strchr(curr_entry, ';');
				if (next_entry != NULL) {
					next_entry[0] = '\0';
					next_entry = next_entry + 1;
				}

				int enter_or_leave;
				long room_id;
				unsigned long time;
				sscanf(curr_entry, "%dR%ldT%lu", &enter_or_leave, &room_id, &time);

				if (enter_or_leave == 1 && room_id != GALLERY_ID) {
					if (found_entry) {
						putchar(',');
					} else {
						found_entry = 1;
					}
					printf("%ld", room_id);
				}

				curr_entry = next_entry;
			}

			if (found_entry) {
				putchar('\n');
			}
		}

		line = line + line_length + 1;
	}
}

void print_occupied_rooms(char *log, struct person_node *employee_list, struct person_node *guest_list) {
	int line_length = 0;
	//struct room_node *room_list = NULL;

	char *line = log;
	while ((line_length = get_current_line_length(line)) > 0) {
		line[line_length] = '\0';

		unsigned long name_length = 0;
		int i;
		for (i = 2; line[i] != ' '; i++) {
			name_length++;
		}
		char *name = malloc(name_length + 1);
		strncpy(name, &line[2], name_length);
		name[name_length] = '\0';

		if ((line[0] == 'E' && person_list_contains(employee_list, name, 'E')) || (line[0] == 'G' && person_list_contains(guest_list, name, 'G'))) {
			char *curr_entry = strchr(&line[2], ';');
			if (curr_entry != NULL) {
				curr_entry = curr_entry + 1;
			}

			while (curr_entry != NULL) {
				int enter_or_leave;
				long room_id;
				unsigned long time;
				sscanf(curr_entry, "%dR%ldT%lu", &enter_or_leave, &room_id, &time);



				curr_entry = strchr(curr_entry, ';');
				if (curr_entry != NULL) {
					curr_entry = curr_entry + 1;
				}
			}
		}

		free(name);
		line = line + line_length + 1;
	}
}

void print_time_spent(char *log, char *name, char person_type) {
	int line_length;

	char *line = log;
	while ((line_length = get_current_line_length(line)) > 0) {
		if (line[0] == person_type && strncmp(name, &line[2], strlen(name)) == 0) {
			line[line_length] = '\0';

			char *curr_entry = strchr(&line[2], ' ');
			if (curr_entry == NULL) {
				return;
			} else {
				curr_entry = curr_entry + 1;
			}

			unsigned long time_spent = 0, enter_time = 0, current_time = 0;
			while (curr_entry != NULL) {
				int enter_or_leave;
				long room_id;
				sscanf(curr_entry, "%dR%ldT%lu", &enter_or_leave, &room_id, &current_time);

				if (enter_or_leave == 1 && room_id == GALLERY_ID) {
					enter_time = current_time;
				} else if (enter_or_leave == 0 && room_id == GALLERY_ID) {
					time_spent += current_time - enter_time;
					enter_time = 0;
				}

				curr_entry = strchr(curr_entry, ';');
				if (curr_entry != NULL) {
					curr_entry = curr_entry + 1;
				}
			}

			if (enter_time != 0) {
				time_spent += current_time - enter_time;
			}

			printf("%lu\n", time_spent);
			return;
		}

		line = line + line_length + 1;
	}
}

int main(int argc, char *argv[]) {
	int opt, s_opt = 0, r_opt = 0, t_opt = 0, i_opt = 0;
	char *log_path = NULL, *key = NULL, *employee_name = NULL, *guest_name = NULL;

  	while ((opt = getopt(argc, argv, OPT_STRING)) != -1) {
    	switch (opt) {
    		case 'K':
    			key = optarg;
        		break;

        	case 'S':
      			s_opt = 1;
        		break;

        	case 'R':
        		r_opt = 1;
        		break;

      		case 'T':
      			t_opt = 1;
        		break;

        	case 'I':
        		printf("unimplemented\n");
        		exit(ERROR_CODE);

        	case 'E':
        		employee_name = optarg;
        		break;

        	case 'G':
        		guest_name = optarg;
        		break;

        	case '?':
        		printf("invalid\n");
        		//printf("Invalid command-line argument\n");
        		exit(ERROR_CODE);

        	default:
        		//printf("Reached default branch of switch\n");
        		printf("invalid\n");
        		exit(ERROR_CODE);
    	}
  	}

  	if (optind < argc) {
    	log_path = argv[optind];
  	}

  	if (key == NULL || log_path == NULL || (s_opt + r_opt + t_opt + i_opt != 1)) {
  		//printf("Invalid arguments\n");
  		printf("invalid\n");
  		exit(ERROR_CODE);
  	}

  	FILE *log_file = fopen(log_path, "r");
  	if (log_file == NULL) {
  		//printf("Unable to open log file\n");
  		printf("invalid\n");
  		exit(ERROR_CODE);
  	}

  	char *decrypted_text = (char *)decrypt_file(log_file, generate_key(key));

  	if (s_opt) {
  		if (employee_name != NULL || guest_name != NULL) {
  			printf("invalid\n");
  			//printf("Invalid arguments for -S\n");
  			exit(ERROR_CODE);
  		} else {
  			print_current_state(decrypted_text);
  		}
  	}

  	if (r_opt) {
  		if ((employee_name == NULL && guest_name == NULL) || (employee_name != NULL && guest_name != NULL)) {
  			//printf("Invalid arguments for -R\n");
  			printf("invalid\n");
  			exit(ERROR_CODE);
  		}

  		if (employee_name != NULL) {
  			print_rooms_entered(decrypted_text, employee_name, 'E');
  		} else {
  			print_rooms_entered(decrypted_text, guest_name, 'G');
  		}
  	}

  	if (t_opt) {
  		if ((employee_name == NULL && guest_name == NULL) || (employee_name != NULL && guest_name != NULL)) {
  			printf("invalid\n");
  			exit(ERROR_CODE);
  		}

  		if (employee_name != NULL) {
  			print_time_spent(decrypted_text, employee_name, 'E');
  		} else {
  			print_time_spent(decrypted_text, guest_name, 'G');
  		}
  	}

  	return 0;
}
