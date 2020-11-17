/*
    lib info    : SHIKI_LIB_GROUP - SYS_LINUX
    ver         : 1.02.20.05.12
    author      : Jaya Wikrama, S.T.
    e-mail      : jayawikrama89@gmail.com
    Copyright (c) 2019 HANA,. Jaya Wikrama

    Support     : tcp-ip client/server
                : tcp-ip ssl client
                : http request
*/

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <linux/input.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include "shiki-system-tools.h"

int8_t ssys_debug_mode_status = 1;

static void ssys_debug(const char *function_name, const char *debug_type, const char *debug_msg, ...);
static int *ssys_keyboard_thread(void *_timeout);
static char *ssys_list_dir_by_name(const char *_dir_path, const char *_keyword, uint8_t _type);
static char *ssys_list_dir(const char *_dir_path, uint8_t _type);

static void ssys_debug(const char *function_name, const char *debug_type, const char *debug_msg, ...){
	if (ssys_debug_mode_status == 1 || strcmp(debug_type, "INFO") != 0){
        struct tm *d_tm = NULL;
        struct timeval tm_debug;
        uint16_t msec = 0;
		
	    gettimeofday(&tm_debug, NULL);
	    d_tm = localtime(&tm_debug.tv_sec);
        msec = tm_debug.tv_usec/1000;

        #ifdef __linux__
            if (strcmp(debug_type, "INFO")==0)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SSYS\033[1;32m %s\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, debug_type, function_name
                );
            if (strcmp(debug_type, "WEBSERVER INFO")==0)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SSYS\033[1;32m %s\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, debug_type, function_name
                );
    	    else if (strcmp(debug_type, "WARNING")==0)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SSYS\033[1;33m %s\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, debug_type, function_name
                );
    	    else if (strcmp(debug_type, "ERROR")==0)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SSYS\033[1;31m %s\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, debug_type, function_name
                );
            else if (strcmp(debug_type, "CRITICAL")==0)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SSYS\033[1;31m %s\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, debug_type, function_name
                );
	    #else
            printf("%02d-%02d-%04d %02d:%02d:%02d.%03d %s: %s: ",
             d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
             msec, debug_type, function_name
            );
        #endif

        va_list aptr;
        va_start(aptr, debug_msg);
	    vfprintf(stdout, debug_msg, aptr);
	    va_end(aptr);
    }
}

// keyboard
char *ssys_get_keyboard_file(){
    DIR *d_fd = NULL;
    struct dirent *d_st = NULL;
    if ((d_fd = opendir("/dev/input/by-path")) == NULL){
        ssys_debug(__func__, "ERROR", "fail to open directory \"/dev/input/by-path\"\n");
        return NULL;
    }
    char *file_name = NULL;
    file_name = (char *) malloc(8*sizeof(char));
    if (file_name == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate file_name memory\n");
        closedir(d_fd);
        d_fd = NULL;
    }
    while((d_st = readdir(d_fd)) != NULL){
        if (d_st->d_name[strlen(d_st->d_name)-3] == 'k' &&
         d_st->d_name[strlen(d_st->d_name)-2] == 'b' &&
         d_st->d_name[strlen(d_st->d_name)-1] == 'd'
        ){
            file_name = (char *) realloc(file_name, (strlen(d_st->d_name) + 1)*sizeof(char));
            strcpy(file_name, d_st->d_name);
            closedir(d_fd);
            d_fd = NULL;
            return file_name;
        }
    }
    closedir(d_fd);
    d_fd = NULL;
    ssys_debug(__func__, "ERROR", "can't found keyboard input file\n");
    return NULL;
}

FILE *ssys_open_keyboard(const char *_file_name){
    if (_file_name == NULL){
        ssys_debug(__func__, "ERROR", "file name undefined\n");
        return NULL;
    }
    if (strlen(_file_name) == 0){
        ssys_debug(__func__, "ERROR", "file name is missing\n");
        return NULL;
    }
    FILE *f_key = NULL;
    char f_path[20 + strlen(_file_name)];
    memset(f_path, 0x00, (20 + strlen(_file_name))*sizeof(char));
    sprintf(f_path, "/dev/input/by-path/%s", _file_name);
    if ((f_key = fopen(f_path, "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to open %s\n", f_path);
        return NULL;
    }
    return f_key;
}

void ssys_close_keyboard(FILE **_file_descriptor){
    if (*_file_descriptor != NULL){
        fclose(*_file_descriptor);
        *_file_descriptor = NULL;
    }
}

int16_t ssys_get_keyboard_input(FILE *_file_descriptor, char *_key_name, uint16_t _timeout_ms){
    if (_file_descriptor == NULL){
        ssys_debug(__func__, "ERROR", "file name undefined\n");
        return -1;
    }
    if (_key_name == NULL){
        ssys_debug(__func__, "ERROR", "key name undefined\n");
        return -1;
    }
    struct input_event kb_input;
    uint16_t timeout_tmp = _timeout_ms;
    // wait until input is aviable
    while(fread(&kb_input, sizeof(kb_input), 1, _file_descriptor) == 0) {
        usleep(1000);
        timeout_tmp--;
        if(_timeout_ms > 0 && !timeout_tmp){
            ssys_debug(__func__, "WARNING", "request timeout\n");
            return -2;
        }
    }
    int16_t key_num = (int16_t) kb_input.value;
    switch(key_num){
        case 1 :
            strcpy(_key_name, "[ESC]");
        break;
        case 2 :
            strcpy(_key_name, "1");
        break;
        case 3 :
            strcpy(_key_name, "2");
        break;
        case 4 :
            strcpy(_key_name, "3");
        break;
        case 5 :
            strcpy(_key_name, "4");
        break;
        case 6 :
            strcpy(_key_name, "5");
        break;
        case 7 :
            strcpy(_key_name, "6");
        break;
        case 8 :
            strcpy(_key_name, "7");
        break;
        case 9 :
            strcpy(_key_name, "8");
        break;
        case 10 :
            strcpy(_key_name, "9");
        break;
        case 11 :
            strcpy(_key_name, "0");
        break;
        case 12 :
            strcpy(_key_name, "-");
        break;
        case 13 :
            strcpy(_key_name, "=");
        break;
        case 14 :
            strcpy(_key_name, "[BACKSPACE]");
        break;
        case 15 :
            strcpy(_key_name, "[TAB]");
        break;
        case 16 :
            strcpy(_key_name, "q");
        break;
        case 17 :
            strcpy(_key_name, "w");
        break;
        case 18 :
            strcpy(_key_name, "e");
        break;
        case 19 :
            strcpy(_key_name, "r");
        break;
        case 20 :
            strcpy(_key_name, "t");
        break;
        case 21 :
            strcpy(_key_name, "y");
        break;
        case 22 :
            strcpy(_key_name, "u");
        break;
        case 23 :
            strcpy(_key_name, "i");
        break;
        case 24 :
            strcpy(_key_name, "o");
        break;
        case 25 :
            strcpy(_key_name, "p");
        break;
        case 26 :
            strcpy(_key_name, "[");
        break;
        case 27 :
            strcpy(_key_name, "]");
        break;
        case 28 :
            strcpy(_key_name, "[ENTER]");
        break;
        case 29 :
            strcpy(_key_name, "L_CTRL");
        break;
        case 30 :
            strcpy(_key_name, "a");
        break;
        case 31 :
            strcpy(_key_name, "s");
        break;
        case 32 :
            strcpy(_key_name, "d");
        break;
        case 33 :
            strcpy(_key_name, "f");
        break;
        case 34 :
            strcpy(_key_name, "g");
        break;
        case 35 :
            strcpy(_key_name, "h");
        break;
        case 36 :
            strcpy(_key_name, "j");
        break;
        case 37 :
            strcpy(_key_name, "k");
        break;
        case 38 :
            strcpy(_key_name, "l");
        break;
        case 39 :
            strcpy(_key_name, ";");
        break;
        case 40 :
            strcpy(_key_name, "'");
        break;
        case 41 :
            strcpy(_key_name, "`");
        break;
        case 42 :
            strcpy(_key_name, "L_SHIFT");
        break;
        case 43 :
            strcpy(_key_name, "\\");
        break;
        case 44 :
            strcpy(_key_name, "z");
        break;
        case 45 :
            strcpy(_key_name, "x");
        break;
        case 46 :
            strcpy(_key_name, "c");
        break;
        case 47 :
            strcpy(_key_name, "v");
        break;
        case 48 :
            strcpy(_key_name, "b");
        break;
        case 49 :
            strcpy(_key_name, "n");
        break;
        case 50 :
            strcpy(_key_name, "m");
        break;
        case 51 :
            strcpy(_key_name, ",");
        break;
        case 52 :
            strcpy(_key_name, ".");
        break;
        case 53 :
            strcpy(_key_name, "/");
        break;
        case 54 :
            strcpy(_key_name, "R_SHIFT");
        break;
        case 55 :
            strcpy(_key_name, "m");
        break;
        case 56 :
            strcpy(_key_name, "L_ALT");
        break;
        case 57 :
            strcpy(_key_name, " ");
        break;
        case 58 :
            strcpy(_key_name, "[CAPSLOCK]");
        break;
        case 59 :
            strcpy(_key_name, "[F1]");
        break;
        case 60 :
            strcpy(_key_name, "[F2]");
        break;
        case 61 :
            strcpy(_key_name, "[F3]");
        break;
        case 62 :
            strcpy(_key_name, "[F4]");
        break;
        case 63 :
            strcpy(_key_name, "[F5]");
        break;
        case 64 :
            strcpy(_key_name, "[F6]");
        break;
        case 65 :
            strcpy(_key_name, "[F7]");
        break;
        case 66 :
            strcpy(_key_name, "[F8]");
        break;
        case 67 :
            strcpy(_key_name, "[F9]");
        break;
        case 68 :
            strcpy(_key_name, "[F10]");
        break;
        case 69 :
            strcpy(_key_name, "[F9]");
        break;
        case 70 :
        break;
        case 71 :
        break;
        case 72 :
        break;
        case 73 :
        break;
        case 74 :
        break;
        case 75 :
        break;
        case 76 :
        break;
        case 77 :
        break;
        case 78 :
        break;
        case 79 :
        break;
        case 80 :
        break;
        case 81 :
        break;
        case 82 :
        break;
        case 83 :
        break;
        case 84 :
        break;
        case 85 :
        break;
        case 86 :
        break;
        case 87 :
            strcpy(_key_name, "[F11]");
        break;
        case 88 :
            strcpy(_key_name, "[F12]");
        break;
        case 89 :
        break;
        case 90 :
        break;
        case 157 :
            strcpy(_key_name, "[R_CTRL]");
        break;
        case 183 :
            strcpy(_key_name, "[PRTSCR]");
        break;
        case 184 :
            strcpy(_key_name, "[R_ALT]");
        break;
        case 200 :
            strcpy(_key_name, "[KEY_UP]");
        break;
        case 203 :
            strcpy(_key_name, "[KEY_LEFT]");
        break;
        case 205 :
            strcpy(_key_name, "[KEY_RIGHT]");
        break;
        case 208 :
            strcpy(_key_name, "[KEY_DOWN]");
        break;
        case 210 :
            strcpy(_key_name, "[WINDOW]");
        break;
    }
    return (int16_t) kb_input.value;
}

int8_t ssys_get_keyboard_plug_status(){
    char *list_event = ssys_list_directory_by_name("/sys/class/input", "event");
    if (list_event == NULL) {
        return -1;
    }
    uint16_t dir_name_size = 8;
    char *dir_name = NULL;
    dir_name = (char *) malloc(dir_name_size*sizeof(char));
    if (dir_name == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate dir_name memory\n");
        free(list_event);
        list_event = NULL;
    }
    memset(dir_name, 0x00, dir_name_size*sizeof(char));
    uint16_t num_of_event = 0;
    uint16_t i = 0;
    uint16_t list_event_length = (uint16_t) strlen(list_event);
    uint8_t idx_char = 0;
    for (i=0; i<list_event_length; i++){
        if (list_event[i] == '\n'){
            dir_name[idx_char] = 0x00;
            char file_full_path[32 + idx_char];
            memset(file_full_path, 0x00, sizeof(file_full_path));
            sprintf(file_full_path, "/sys/class/input/%s/device/uevent", dir_name);
            if(ssys_check_text_in_file(file_full_path, "keyboard") == 0 ||
             ssys_check_text_in_file(file_full_path, "Keyboard") == 0 ||
             ssys_check_text_in_file(file_full_path, "KEYBOARD") == 0
            ){
                ssys_debug(__func__, "INFO", "keyboard detected\n");
                num_of_event++;
            }
            memset(dir_name, 0x00, dir_name_size*sizeof(char));
            if (dir_name_size != 8){
                dir_name_size = 8;
                dir_name = (char *) realloc(dir_name, dir_name_size*sizeof(char));
            }
            idx_char = 0;
        }
        else {
            if ((idx_char+1) == dir_name_size){
                dir_name_size+=8;
                dir_name = (char *) realloc(dir_name, dir_name_size*sizeof(char));
            }
            dir_name[idx_char] = list_event[i];
            idx_char++;
        }
    }
    free(list_event);
    free(dir_name);
    list_event = NULL;
    dir_name = NULL;
    if (num_of_event == 0){
        return -1;
    }
    return num_of_event;
}

static int *ssys_keyboard_thread(void *_timeout){
    char *file_name = ssys_get_keyboard_file();
    if (file_name == NULL){
        return NULL;
    }
    ssys_debug(__func__, "INFO", "%s\n", file_name);
    FILE *k_fd = ssys_open_keyboard(file_name);
    if (k_fd == NULL){
        free(file_name);
        file_name = NULL;
        return NULL;
    }
    free(file_name);
    file_name = NULL;
    while(1) {
        start:
            ssys_debug(__func__, "INFO", "wait input\n");
            skey_data.key_value = ssys_get_keyboard_input(k_fd, skey_data.key_name, (uint16_t) (long) _timeout);
            if (skey_data.key_value >= 0){
                ssys_debug(__func__, "INFO", "keyboard input : %d - %s\n", skey_data.key_value, skey_data.key_name);
                usleep(1000);
            }
            goto start;
        reopen_keyboard:
            file_name = ssys_get_keyboard_file();
            if (file_name == NULL){
                sleep(1);
                goto reopen_keyboard;
            }
            ssys_close_keyboard(&k_fd);
            k_fd = ssys_open_keyboard(file_name);
            if (k_fd == NULL){
                free(file_name);
                file_name = NULL;
                return NULL;
            }
            free(file_name);
            file_name = NULL;
            goto start;
    }
    ssys_close_keyboard(&k_fd);
    return NULL;
}

int8_t ssys_keyboard_thread_start(){
	pthread_t kbd_thread;
	if(pthread_create(&kbd_thread, NULL, (void* (*)(void *)) ssys_keyboard_thread, NULL) == 0) {
		ssys_debug(__func__, "INFO", "thread started successfully\n");
		return 0;
	}
	else ssys_debug(__func__, "ERROR", "thread start failed\n");
	return -1;
}

// temperature
float ssys_get_temperature(){
    FILE *f_temp = NULL;
    if ((f_temp = fopen("/sys/class/thermal/thermal_zone0/temp", "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to read temperature\n");
        return -1;
    }

    char buff[6];
    memset(buff, 0x00, 6*sizeof(char));
    if(fread(&buff, 5, 1, f_temp) > 0){
        float temp;
        temp = atof(buff)/1000;
        fclose(f_temp);
        f_temp = NULL;
        return temp;
    }
    fclose(f_temp);
    f_temp = NULL;
    return -99.0;
}

// file and directory
static char *ssys_list_dir(const char *_dir_path, uint8_t _type){
    DIR *d_fd = NULL;
    struct dirent *d_st = NULL;
    if ((d_fd = opendir(_dir_path)) == NULL){
        ssys_debug(__func__, "ERROR", "fail to open directory \"%s\"\n", _dir_path);
        return NULL;
    }
    uint16_t dir_count = 0;
    uint16_t str_length = 0;
    char *dir_list = NULL;
    dir_list = (char *) malloc(3*sizeof(char));
    if (dir_list == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memory\n");
        closedir(d_fd);
        return NULL;
    }
    memset(dir_list, 0x00, 3*sizeof(char));
    while((d_st = readdir(d_fd)) != NULL){
        if (d_st->d_type == _type || (_type == 4 && d_st->d_type == 10)){
            str_length = str_length + strlen(d_st->d_name) + 1;
            dir_list = (char *) realloc(dir_list, (str_length + 1)*sizeof(char));
            strcat(dir_list, d_st->d_name);
            dir_list[str_length - 1] = '\n';
            dir_list[str_length] = 0x00;
            dir_count++;
        }
    }
    closedir(d_fd);
    d_fd = NULL;
    if (dir_count > 0){
        if (_type == 4){
            ssys_debug(__func__, "INFO", "found %d directories\n", dir_count);
        }
        if (_type == 8){
            ssys_debug(__func__, "INFO", "found %d files\n", dir_count);
        }
    }
    else {
        if (_type == 4){
            ssys_debug(__func__, "WARNING", "no directory found\n");
        }
        else if (_type == 8){
            ssys_debug(__func__, "WARNING", "no file found\n");
        }
        else {
            ssys_debug(__func__, "ERROR", "wrong type\n");
        }
        free(dir_list);
        return NULL;
    }
    return dir_list;
}

static char *ssys_list_dir_by_name(const char *_dir_path, const char *_keyword, uint8_t _type){
    DIR *d_fd = NULL;
    struct dirent *d_st = NULL;
    if ((d_fd = opendir(_dir_path)) == NULL){
        ssys_debug(__func__, "ERROR", "fail to open directory \"%s\"\n", _dir_path);
        return NULL;
    }
    uint16_t dir_count = 0;
    uint16_t str_length = 0;
    char *dir_list = NULL;
    dir_list = (char *) malloc(3*sizeof(char));
    if (dir_list == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memory\n");
        closedir(d_fd);
        return NULL;
    }
    memset(dir_list, 0x00, 3*sizeof(char));
    while((d_st = readdir(d_fd)) != NULL){
        if ((d_st->d_type == _type || (_type == 4 && d_st->d_type == 10)) && strlen(d_st->d_name) >= strlen(_keyword)){
            if (_keyword[0]=='*' && _keyword[1]=='.'){
                if (strstr(d_st->d_name, (_keyword + 1)) != NULL){
                    str_length = str_length + strlen(d_st->d_name) + 1;
                    dir_list = (char *) realloc(dir_list, (str_length + 1)*sizeof(char));
                    strcat(dir_list, d_st->d_name);
                    dir_list[str_length - 1] = '\n';
                    dir_list[str_length] = 0x00;
                    dir_count++;
                }
            }
            else if (strstr(d_st->d_name, _keyword) != NULL){
                str_length = str_length + strlen(d_st->d_name) + 1;
                dir_list = (char *) realloc(dir_list, (str_length + 1)*sizeof(char));
                strcat(dir_list, d_st->d_name);
                dir_list[str_length - 1] = '\n';
                dir_list[str_length] = 0x00;
                dir_count++;
            }
        }
    }
    closedir(d_fd);
    d_fd = NULL;
    if (dir_count == 0) {
        if (_type == 4){
            ssys_debug(__func__, "WARNING", "no directory found\n");
        }
        else if (_type == 8){
            ssys_debug(__func__, "WARNING", "no directory found\n");
        }
        else {
            ssys_debug(__func__, "ERROR", "wrong type\n");
        }
        free(dir_list);
        return NULL;
    }
    return dir_list;
}

char *ssys_list_directory(const char *_dir_path){
    return ssys_list_dir(_dir_path, 4);
}

char *ssys_list_file(const char *_dir_path){
    return ssys_list_dir(_dir_path, 8);
}

char *ssys_list_directory_by_name(const char *_dir_path, const char *_keyword){
    return ssys_list_dir_by_name(_dir_path, _keyword, 4);
}

char *ssys_list_file_by_name(const char *_dir_path, const char *_keyword){
    return ssys_list_dir_by_name(_dir_path, _keyword, 8);
}

char *ssys_list_file_by_content(const char *_dir_path, const char *_keyword){
    DIR *d_fd = NULL;
    struct dirent *d_st = NULL;
    if ((d_fd = opendir(_dir_path)) == NULL){
        ssys_debug(__func__, "ERROR", "fail to open directory \"%s\"\n", _dir_path);
        return NULL;
    }
    uint16_t dir_count = 0;
    uint16_t str_length = 0;
    uint8_t _type = 8;
    char *dir_list = NULL;
    dir_list = (char *) malloc(3*sizeof(char));
    if (dir_list == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memory\n");
        closedir(d_fd);
        return NULL;
    }
    memset(dir_list, 0x00, 3*sizeof(char));
    while((d_st = readdir(d_fd)) != NULL){
        if (d_st->d_type == _type){
            char file_full_path[strlen(_dir_path) + strlen(d_st->d_name) + 2];
            memset(file_full_path, 0x00, (strlen(_dir_path) + strlen(d_st->d_name) + 2)*sizeof(char));
            sprintf(file_full_path, "%s/%s", _dir_path, d_st->d_name);
            if (ssys_check_text_in_file(file_full_path, _keyword) == 0){
                str_length = str_length + strlen(d_st->d_name) + 1;
                dir_list = (char *) realloc(dir_list, (str_length + 1)*sizeof(char));
                strcat(dir_list, d_st->d_name);
                dir_list[str_length - 1] = '\n';
                dir_list[str_length] = 0x00;
                dir_count++;
            }
        }
    }
    closedir(d_fd);
    d_fd = NULL;
    if (dir_count > 0){
        if (_type == 4){
            ssys_debug(__func__, "INFO", "found %d directories\n", dir_count);
        }
        if (_type == 8){
            ssys_debug(__func__, "INFO", "found %d files\n", dir_count);
        }
    }
    else {
        if (_type == 4){
            ssys_debug(__func__, "WARNING", "no directory found\n");
        }
        else if (_type == 8){
            ssys_debug(__func__, "WARNING", "no directory found\n");
        }
        else {
            ssys_debug(__func__, "ERROR", "wrong type\n");
        }
        free(dir_list);
        dir_list = NULL;
        return NULL;
    }
    return dir_list;
}

int8_t ssys_check_text_in_file(const char *_file, const char *_keyword){
    FILE *f_check = NULL;
    if ((f_check = fopen(_file, "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to read \"%s\"\n", _file);
        return -1;
    }

    char buff[strlen(_keyword) + 1];
    char character = 0;
    memset(buff, 0x00, sizeof(buff));
    uint8_t i = 0;
    for (i=0; i<strlen(_keyword); i++){
        character = fgetc(f_check);
        if (character == EOF){
            break;
        }
        buff[i] = character;
    }
    if (strlen(buff) < strlen(_keyword)){
        fclose(f_check);
        f_check = NULL;
        return -1;
    }
    if (strcmp(buff, _keyword) == 0){
        fclose(f_check);
        f_check = NULL;
        return 0;
    }
    else if (character == EOF){
        fclose(f_check);
        f_check = NULL;
        return -1;
    }

    while ((character = fgetc(f_check)) != EOF){
        if (character < 1 || character > 127) break;
        for (i=0; i<strlen(_keyword) - 1; i++){
            buff[i] = buff[i + 1];
        }
        buff[strlen(_keyword) - 1] = character;
        if (strcmp(buff, _keyword) == 0){
            fclose(f_check);
            return 0;
        }
    }
    fclose(f_check);
    f_check = NULL;
    return -1;
}

unsigned long ssys_get_file_size(const char *_file){
    FILE *f_check;
    if ((f_check = fopen(_file, "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to read \"%s\"\n", _file);
        return 0;
    }

    fseek(f_check, 0L, SEEK_END);
    unsigned long file_size = ftell(f_check);
    fclose(f_check);

    return file_size;
}

int8_t ssys_get_checksum_of_file(const char *_file_name, unsigned char *_checksum_output){
	FILE *fd_sum = NULL;
    fd_sum = fopen(_file_name, "rb");
	if (fd_sum == NULL){
		ssys_debug(__func__, "ERROR", "fail to open file\n");
		return -1;
	}

	int bytes = 0;
	unsigned char *data = NULL;
	unsigned char *sum = NULL;
	unsigned char *md5_sum = NULL;

	data = (unsigned char *) malloc(512*sizeof(char));
	if (data == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate data memory\n");
		return -1;
	}
	sum = (unsigned char *) malloc(MD5_DIGEST_LENGTH*sizeof(char));
	if (sum == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate sum memory\n");
		free(data);
        data = NULL;
		return -1;
	}
	md5_sum = (unsigned char *) malloc(33*sizeof(char));
	if (md5_sum == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate md5_sum memory\n");
		free(data);
		free(sum);
        data = NULL;
        sum = NULL;
		return -1;
	}

    MD5_CTX context;
	MD5_Init(&context);

	while ((bytes = fread(data, 1, 512, fd_sum)) != 0){
		MD5_Update(&context, data, bytes);
	}

    MD5_Final(sum, &context);

	memset(md5_sum, 0x00, 33*sizeof(char));
	for (int i=0; i < MD5_DIGEST_LENGTH; i++){
		sprintf((char *) &md5_sum[i*2], "%02x", (unsigned int)sum[i]);
	}
	fclose(fd_sum);
    fd_sum = NULL;
	strcpy((char *)_checksum_output, (char *)md5_sum);
	ssys_debug(__func__, "INFO", "checksum of \"%s\" is %s\n", _file_name, md5_sum);
	free(data);
	free(sum);
	free(md5_sum);
    data = NULL;
    sum = NULL;
    md5_sum = NULL;
	return 0;
}

int8_t ssys_get_checksum(const unsigned char *_input, unsigned char *_checksum_output){
	MD5_CTX context;
	MD5_Init(&context);

	unsigned char *sum = NULL;
	unsigned char *md5_sum = NULL;

	sum = (unsigned char *) malloc(MD5_DIGEST_LENGTH*sizeof(char));
	if (sum == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate sum memory\n");
		return -1;
	}
	md5_sum = (unsigned char *) malloc(33*sizeof(char));
	if (md5_sum == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate md5_sum memory\n");
		free(sum);
        sum = NULL;
		return -1;
	}

	MD5_Update(&context, _input, strlen((char *)_input));
	MD5_Final(sum, &context);

	memset(md5_sum, 0x00, 33*sizeof(char));
	for (int i=0; i< MD5_DIGEST_LENGTH; i++){
		sprintf((char *) &md5_sum[i*2], "%02x", (unsigned int)sum[i]);
	}

	strcpy((char *)_checksum_output, (char *)md5_sum);
	ssys_debug(__func__, "INFO", "checksum of \"%s\" is %s\n", _input, md5_sum);
	free(sum);
	free(md5_sum);
    sum = NULL;
    md5_sum = NULL;
	return 0;
}

char *ssys_encode_base64(unsigned char *_buff, size_t _length){
    char *result = NULL;
    size_t result_size = _length + 1;
    result = (char *) malloc(result_size * sizeof(char));
    if (result == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memmory\n");
        return NULL;
    }
    memset(result, 0x00, result_size * sizeof(char));

    char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int index = 0;
    int no_of_bits = 0;
    size_t padding = 0;
    int val = 0;
    int count = 0;
    int temp = 0;
    size_t i, j;
    size_t idx_result = 0; 

    for (i = 0; i < _length; i += 3){ 
        val = 0;
        count = 0;
        no_of_bits = 0;
        for (j = i; j < _length && j <= i + 2; j++){
            val = val << 8;
            val = val | _buff[j];
            count++;
        } 
        no_of_bits = count * 8;
        padding = no_of_bits % 3;
        while (no_of_bits != 0){
            if (no_of_bits >= 6){ 
                temp = no_of_bits - 6;
                index = (val >> temp) & 63;  
                no_of_bits -= 6;          
            } 
            else{ 
                temp = 6 - no_of_bits;
                index = (val << temp) & 63;  
                no_of_bits = 0; 
            }
            if (result_size <= idx_result + 2){
                result_size += 8;
                result = (char *) realloc(result, result_size * sizeof(char));
            }
            result[idx_result++] = charset[index];
        } 
    }
    for (i = 1; i <= padding; i++)  
    { 
        if (result_size <= idx_result + 2){
            result_size += 8;
            result = (char *) realloc(result, result_size * sizeof(char));
        }
        result[idx_result++] = '=';
    }
    result[idx_result] = 0x00;
    return result;
}

unsigned char *ssys_decode_base64(unsigned char *_buff, size_t _length){
    unsigned char *result = NULL;
    size_t result_size = _length + 1;
    result = (unsigned char *) malloc(result_size * sizeof(unsigned char));
    if (result == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memmory\n");
        return NULL;
    }
    memset(result, 0x00, result_size * sizeof(char));

    size_t i = 0;
    size_t j = 0;
    size_t idx_result = 0;  
    int num = 0;
    int count_bits = 0;
    for (i = 0; i < _length; i += 4){ 
        num = 0, count_bits = 0;
        for (j = 0; j < 4; j++){
            if (_buff[i + j] != '='){
                num = num << 6;
                count_bits += 6;
            }
            if (_buff[i + j] >= 'A' && _buff[i + j] <= 'Z'){
                num = num | (_buff[i + j] - 'A');
            }
            else if (_buff[i + j] >= 'a' && _buff[i + j] <= 'z'){
                num = num | (_buff[i + j] - 'a' + 26);
            }
            else if (_buff[i + j] >= '0' && _buff[i + j] <= '9'){
                num = num | (_buff[i + j] - '0' + 52);
            }
            else if (_buff[i + j] == '+'){
                num = num | 62;
            }
            else if (_buff[i + j] == '/'){
                num = num | 63;
            }
            else if (_buff[i + j] == 0x00 ||
             _buff[i + j] == '='
            ) { 
                num = num >> 2; 
                count_bits -= 2; 
            }
            else {
                free(result);
                result = NULL;
                return NULL;
            }
        } 
        while (count_bits != 0) { 
            count_bits -= 8;
            if (result_size <= idx_result + 2){
                result_size += 8;
                result = (unsigned char *) realloc(result, result_size * sizeof(unsigned char));
            }
            result[idx_result++] = (num >> count_bits) & 0xFF;
        } 
    }
    result[idx_result] = 0x00;
    return result;
}

unsigned char *ssys_encrypt_aes_cbc(
 const unsigned char *_input_data,
 const unsigned char *_encrypt_key,
 const unsigned char *_iv,
 uint16_t _data_size
){
    if (_input_data == NULL){
        ssys_debug(__func__, "ERROR", "null data\n");
        return NULL;
    }
    unsigned char *data_enc = NULL;
    data_enc = (unsigned char *) malloc((_data_size + 1) * sizeof(unsigned char));
    if (data_enc == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memory\n");
        return NULL;
    }

    memset(data_enc, 0x00, (_data_size + 1) * sizeof(unsigned char));
    AES_KEY enc_key;
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, sizeof(iv));
    strncpy((char *) iv, (char *)_iv, sizeof(iv));
    AES_set_encrypt_key(_encrypt_key, 128, &enc_key);
    AES_cbc_encrypt(_input_data, data_enc, _data_size, &enc_key, iv, AES_ENCRYPT);
    return data_enc;
}

unsigned char *ssys_decrypt_aes_cbc(
 const unsigned char *_input_data,
 const unsigned char *_decrypt_key,
 const unsigned char *_iv,
 uint16_t _data_size
){
    if (_input_data == NULL){
        ssys_debug(__func__, "ERROR", "null data\n");
        return NULL;
    }
    unsigned char *data_dec = NULL;
    data_dec = (unsigned char *) malloc((_data_size + 1) * sizeof(unsigned char));
    if (data_dec == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memory\n");
        return NULL;
    }
    unsigned char iv[AES_BLOCK_SIZE];
    memset(data_dec, 0x00, (_data_size + 1) * sizeof(unsigned char));
    AES_KEY dec_key;
    memset(iv, 0x00, sizeof(iv));
    strncpy((char *) iv, (const char *)_iv, sizeof(iv));
    AES_set_decrypt_key(_decrypt_key, 128, &dec_key);
    AES_cbc_encrypt(_input_data, data_dec, _data_size, &dec_key, iv, AES_DECRYPT);
    return data_dec;
}

// mac address
int8_t ssys_get_mac_address(char* _mac_address, const char* _interface){
    FILE *mac_file = NULL;
    char *file_name = NULL;
    char *mac_address = NULL;

	file_name = (char *) malloc(35*sizeof(char));
	if (file_name == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate file_name memory\n");
		return -1;
	}
	mac_address = (char *) malloc(18*sizeof(char));
	if (file_name == NULL){
		ssys_debug(__func__, "ERROR", "failed to allocate mac_address memory\n");
		free(file_name);
        file_name = NULL;
		return -1;
	}

    memset(file_name, 0x00, 35*sizeof(char));
    memset(mac_address, 0x00, 18*sizeof(char));
    sprintf(file_name, "/sys/class/net/%s/address", _interface);
    if ((mac_file=fopen(file_name, "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to open %s\n", file_name);
		free(file_name);
		free(mac_address);
        file_name = NULL;
        mac_address = NULL;
        return -2;
    }
    if(fgets(mac_address, 18, mac_file)!=NULL){
		mac_address[17] = 0x00;
        strncpy(_mac_address, mac_address, 18);
        ssys_debug(__func__, "INFO", "your mac address is %s\n", mac_address);
    }
    else{
        ssys_debug(__func__, "INFO", "failed to read mac address\n");
        fclose(mac_file);
		free(file_name);
		free(mac_address);
        mac_file = NULL;
        file_name = NULL;
        mac_address = NULL;
        return -3;
    }
	free(mac_address);
    fclose(mac_file);
    mac_address = NULL;
    mac_file = NULL;
    return 0;
}

// process
uint16_t *sssys_get_process(const char *_keyword, int *_n_proccess){
    DIR *d_fd = NULL;
    struct dirent *d_st = NULL;
    const char _dir_path[] = "/proc";
    if ((d_fd = opendir(_dir_path)) == NULL){
        ssys_debug(__func__, "ERROR", "fail to open directory \"%s\"\n", _dir_path);
        *_n_proccess = 0;
        return NULL;
    }
    uint16_t dir_count = 0;
    uint8_t _type = 4;
    uint16_t *dir_list = NULL;
    dir_list = (uint16_t *) malloc(2*sizeof(uint16_t));
    if (dir_list == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memory\n");
        closedir(d_fd);
        return NULL;
    }
    while((d_st = readdir(d_fd)) != NULL){
        if (d_st->d_type == _type && atol(d_st->d_name) > 0 && atol(d_st->d_name) < 65000){
            char file_full_path[strlen(_dir_path) + strlen(d_st->d_name) + 11];
            memset(file_full_path, 0x00, sizeof(file_full_path));
            sprintf(file_full_path, "%s/%s/cmdline", _dir_path, d_st->d_name);
            if (ssys_check_text_in_file(file_full_path, _keyword) == 0){
                dir_list[dir_count] = (uint16_t) atoi(d_st->d_name);
                dir_count++;
                if (dir_count > 1){
                    dir_list = (uint16_t *) realloc(dir_list, (dir_count+1)*sizeof(uint16_t));
                }
            }
        }
    }
    closedir(d_fd);
    d_fd = NULL;
    if (dir_count > 0){
        ssys_debug(__func__, "INFO", "found %d process\n", dir_count);
        *_n_proccess = dir_count;
    }
    else {
        ssys_debug(__func__, "WARNING", "no process found\n");
        free(dir_list);
        dir_list = NULL;
        *_n_proccess = 0;
        return NULL;
    }
    return dir_list;
}

char *ssys_get_process_command(uint16_t _process_pid){
    FILE *pid_file = NULL;
    char file_name[20];
    memset(file_name, 0x00, sizeof(file_name));
    sprintf(file_name, "/proc/%i/cmdline", _process_pid);
    char *content = NULL;
    content = (char *) malloc(8*sizeof(char));
    if (content == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate content memory\n");
        return NULL;
    }
    if ((pid_file=fopen(file_name, "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to open %s\n", file_name);
        free(content);
        content = NULL;
        return NULL;
    }
    char character = 0;
    uint16_t num_of_bytes = 0;
    uint16_t size_of_buffer = 8;
    while ((character = fgetc(pid_file)) != EOF){
        if (character < 1 || character > 127) break;
        if (num_of_bytes == size_of_buffer - 1){
            size_of_buffer += 8;
            content = (char *) realloc(content, size_of_buffer * sizeof(char));
        }
        content[num_of_bytes] = character;
        num_of_bytes++;
    }
    content[num_of_bytes] = 0x00;
    if (size_of_buffer > num_of_bytes + 1){
        content = (char *) realloc(content, (num_of_bytes + 1) * sizeof(char));
    }
    return content;
}

// bash command
char *ssys_bash_cmd(const char *_command, int *_status_result){
    long time_now = 0;
    char file_name[13];
    char buff[strlen(_command) + 4 + sizeof(file_name)];
    FILE *result_file = NULL;
    char *result = NULL;
    result = (char *) malloc(sizeof(buff));
    uint16_t result_size = 0;
    if (result == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate result memory. process aborted!\n");
        return NULL;
    }
    time(&time_now);
    memset(file_name, 0x00, sizeof(file_name));
    sprintf(file_name, "ssysbcmd%i", (int) (time_now % 3600));
    memset(buff, 0x00, sizeof(buff));
    sprintf(buff, "%s > %s", _command, file_name);

    *_status_result = system(buff);

    if ((result_file=fopen(file_name, "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to open %s. (cmd res: %i)\n", file_name, *_status_result);
		free(result);
        result = NULL;
        return NULL;
    }

    memset(buff, 0x00, sizeof(buff));
    while(fgets(buff, (sizeof(buff) - 1), result_file)!=NULL && result_size < 60000){
        result_size += strlen(buff);
        result = (char *) realloc(result, (result_size + 1) * sizeof(char));
        memcpy(result + (result_size - strlen(buff)), buff, strlen(buff));
        memset(buff, 0x00, sizeof(buff));
    }
    result[result_size] = 0x00;
    fclose(result_file);
    remove(file_name);
    result_file = NULL;
    return result;
}

// tty tools
char *ssys_get_tty_driver(const char *_tty_name){
    FILE *f_check = NULL;
    char file_name[30 + strlen(_tty_name)];
    memset(file_name, 0x00, sizeof(file_name));
    sprintf(file_name, "/sys/class/tty/%s/device/uevent", _tty_name);
    if ((f_check = fopen(file_name, "r")) == NULL){
        ssys_debug(__func__, "ERROR", "failed to read \"%s\"\n", _tty_name);
        return NULL;
    }

    uint16_t buff_size = 8;
    uint16_t idx_buff = 0;
    char *buff = NULL;
    buff = (char *) malloc(buff_size * sizeof(char));
    if (buff == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memory\n");
        fclose(f_check);
        f_check = NULL;
        return NULL;
    }
    char character = 0;
    
    while ((character = fgetc(f_check)) != EOF){
        if (character < 1 || character > 127 || character <= 13) break;
        if (idx_buff >= 7){
            if ((idx_buff - 7) >= buff_size + 2){
                buff_size += 8;
                buff = (char *) realloc(buff, buff_size * sizeof(char));
            }
            buff[idx_buff - 7] = character;
        }
        idx_buff++;
    }
    if (idx_buff >= 7){
        buff[idx_buff - 7] = 0x00;
    }
    buff_size = strlen(buff);
    buff = (char *) realloc(buff, buff_size * sizeof(char));
    fclose(f_check);
    f_check = NULL;
    return buff;
}

char *ssys_get_tty_by_driver(const char *_tty_keyword, const char *_driver_name){
    DIR *d_fd = NULL;
    struct dirent *d_st = NULL;
    if ((d_fd = opendir("/sys/class/tty")) == NULL){
        ssys_debug(__func__, "ERROR", "fail to open tty class directory");
        return NULL;
    }
    char *buff = NULL;
    while((d_st = readdir(d_fd)) != NULL){
        if (strstr(d_st->d_name, _tty_keyword) != NULL){
            buff = ssys_get_tty_driver(d_st->d_name);
            if (buff != NULL){
                if (strcmp(buff, _driver_name) == 0){
                    buff = (char *) realloc(buff, (strlen(d_st->d_name) + 1) * sizeof(char));
                    strcpy(buff, d_st->d_name);
                    break;
                }
                else {
                    free(buff);
                    buff = NULL;
                }
            }
        }
    }
    closedir(d_fd);
    d_fd = NULL;
    return buff;
}

char *ssys_list_tty_driver(const char *_tty_keyword){
    DIR *d_fd = NULL;
    struct dirent *d_st = NULL;
    if ((d_fd = opendir("/sys/class/tty")) == NULL){
        ssys_debug(__func__, "ERROR", "fail to open tty class directory");
        return NULL;
    }
    uint16_t str_length = 0;
    uint16_t str_size = 0;

    char *tty_list = NULL;
    char *buff = NULL;
    tty_list = (char *) malloc(3*sizeof(char));
    if (tty_list == NULL){
        ssys_debug(__func__, "ERROR", "failed to allocate memory\n");
        closedir(d_fd);
        return NULL;
    }
    memset(tty_list, 0x00, 3*sizeof(char));
    while((d_st = readdir(d_fd)) != NULL){
        if (strstr(d_st->d_name, _tty_keyword) != NULL){
            buff = ssys_get_tty_driver(d_st->d_name);
            if (buff != NULL){
                str_size += (strlen(buff) + strlen(d_st->d_name) + 3);
                tty_list = (char *) realloc(tty_list, str_size * sizeof(char));
                memcpy(tty_list + str_length, d_st->d_name, strlen(d_st->d_name));
                str_length += strlen(d_st->d_name);
                tty_list[str_length] = '=';
                str_length++;
                memcpy(tty_list + str_length, buff, strlen(buff));
                str_length += strlen(buff);
                tty_list[str_length] = '\n';
                str_length++;
                free(buff);
                buff = NULL;
            }
            else {
                free(buff);
                buff = NULL;
            }
        }
    }
    closedir(d_fd);
    d_fd = NULL;
    if (str_length == 0){
        free(tty_list);
        tty_list = NULL;
    }
    else {
        tty_list[str_length] = 0x00;
    }
    return tty_list;
}
