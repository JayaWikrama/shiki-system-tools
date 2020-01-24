#ifndef __SHIKI_KEYBOARD_TOOLS__
#define __SHIKI_KEYBOARD_TOOLS__
#include <stdint.h>

// keyboard variable
struct skey_input{
    char key_name[12];
    int key_value;
};

struct skey_input skey_data;

// keyboard function
int8_t ssys_get_keyboard_file(char *_file_name);
int16_t ssys_get_keyboard_input(char *_file_name, char *_key_name);
int8_t ssys_get_keyboard_plug_status();
int8_t ssys_keyboard_thread_start();

float ssys_get_temperature();

char *ssys_list_directory(char *_dir_path);
char *ssys_list_file(char *_dir_path);
char *ssys_list_directory_by_name(char *_dir_path, char *_keyword);
char *ssys_list_file_by_name(char *_dir_path, char *_keyword);
char *ssys_list_file_by_content(char *_dir_path, char *_keyword);
int8_t ssys_check_text_in_file(char *_file, char *_keyword);

#endif