#ifndef CMD_PARSER_H
#define CMD_PARSER_H

#include <linux/string.h>
#include "string.h"

#define EMPTY 0
#define ERROR -1

int parse_cmd( char* cmd , cmd_t* rule );
int rule_init( firebase_t* app , cmd_t *cmd , rule_t* rule );


#endif