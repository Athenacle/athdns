
#ifndef CONFIG_FILE_H
#define CONFIG_FILE_H

#include <stdio.h>

#define KW_NAMESERVER (0x1234)
#define KW_PARALLEL_QUERY (0x1235)

#define KW_CACHE_COUNT (0x1238)
#define KW_LOG (0x1239)
#define KW_LOG_FILE (0x123a)
#define KW_DEFAULT_TTL (0x123f)
#define KW_RE_QUERY (0x1240)
#define KW_SERVER (0x1241)

#define KW_ON (0x1236)
#define KW_OFF (0x1237)

#define KW_LOG_TRACE (0x123b)
#define KW_LOG_ERROR (0x123c)
#define KW_LOG_WARNING (0x123d)
#define KW_LOG_INFO (0x123e)

#define NUMBER (0x1242)
#define IP (0x1243)
#define STRING_TEXT (0x1244)
#define NEWLINE (0x1245)
#define DOMAIN (0x1246)

#define FLEX_EOF (0x1247)

#ifdef __cplusplus
extern "C" {
#endif

extern FILE* yyin;
extern int yylineno;
extern char* yytext;

int yylex(void);
int yylex_destroy(void);

#ifdef __cplusplus
}
#endif

#define YY_NO_UNPUT

#endif
