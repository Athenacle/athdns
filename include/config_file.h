
#ifndef FB_CONFIG_FILE_H
#define FB_CONFIG_FILE_H

#include <stdio.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif

extern FILE* yyin;
extern char* yytext;
extern int yylineno;
extern int yylex(void);
extern int yyerror(const char*);
extern int yyparse(void);
extern int yylex_destroy(void);

//implements in utils.cpp
void config_add_static_ip(const char*, const char*);
void config_add_nameserver(const char*);
void config_set_parallel_query(int);
void config_set_cache_count(int);
void config_set_log_level(int);
void config_set_log_file(const char*);
void config_set_default_ttl(int);
void config_set_requery(int);
void config_set_report_timeout(int);

#ifdef __cplusplus
}
#endif

#define VALUE_ON (0x11)
#define VALUE_OFF (0x111)

#define LOG_TRACE (0xf1)
#define LOG_WARNING (0xf2)
#define LOG_ERROR (0xf3)
#define LOG_INFO (0xf4)
#define LOG_OFF (VALUE_OFF)

#endif
