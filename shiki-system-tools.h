#ifndef __SHIKI_KEYBOARD_TOOLS__
#define __SHIKI_KEYBOARD_TOOLS__
#include <stdint.h>
#include <stdio.h>

// keyboard variable
struct skey_input{
    char key_name[12];
    int key_value;
};

struct skey_input skey_data;

// keyboard function
char *ssys_get_keyboard_file();
FILE *ssys_open_keyboard(char *_file_name);
void ssys_close_keyboard(FILE **_file_descriptor);
int16_t ssys_get_keyboard_input(FILE *_file_descriptor, char *_key_name, uint16_t _timeout_ms);
int8_t ssys_get_keyboard_plug_status();
int8_t ssys_keyboard_thread_start();

float ssys_get_temperature();

char *ssys_list_directory(char *_dir_path);
char *ssys_list_file(char *_dir_path);
char *ssys_list_directory_by_name(char *_dir_path, char *_keyword);
char *ssys_list_file_by_name(char *_dir_path, char *_keyword);
char *ssys_list_file_by_content(char *_dir_path, char *_keyword);
int8_t ssys_check_text_in_file(char *_file, char *_keyword);
unsigned long ssys_get_file_size(char *_file);
int8_t ssys_get_checksum_of_file(char *_file_name, unsigned char *_checksum_output);
int8_t ssys_get_checksum(unsigned char *_input, unsigned char *_checksum_output);
int8_t ssys_get_mac_address(char* _mac_address, char* _interface);

uint16_t *sssys_get_process(char *_keyword, int *_n_proccess);
char *ssys_get_process_command(uint16_t _process_pid);
#endif