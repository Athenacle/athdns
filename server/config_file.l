%e  1019
%p  2807
%n  371
%k  284
%a  1213
%o  1117

DIGIT [0-9]
IP_PART {DIGIT}{1,3}
IP_ADDRESS {IP_PART}\.{IP_PART}\.{IP_PART}\.{IP_PART}
WS [ \t\s\a\r]
TEXT [a-zA-Z0-9/]+
DOMAIN [a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}

%{
#include "config_file.h"

%}

%option yylineno
%option caseless
%option noyywrap

%%

#.*\n                                               {/* comment */ }

{DOMAIN}                                            { return DOMAIN; }

"nameserver"                                        { return KW_NAMESERVER; }
"parallel-query"                                    { return KW_PARALLEL_QUERY; }
"cache-count"                                       { return KW_CACHE_COUNT; }
"log"                                               { return KW_LOG; }
"log-file"                                          { return KW_LOG_FILE; }
"default-ttl"                                       { return KW_DEFAULT_TTL; }
"timeout-requery"                                   { return KW_RE_QUERY; }
"server"                                            { return KW_SERVER; }


"TRACE"                                             { return KW_LOG_TRACE; }
"ERROR"                                             { return KW_LOG_ERROR; }
"WARNING"                                           { return KW_LOG_WARNING; }
"INFO"                                              { return KW_LOG_INFO; }
"ON"                                                { return KW_ON; }
"OFF"                                               { return KW_OFF; }

{DIGIT}+                                            { return NUMBER; }
{IP_ADDRESS}                                        { return IP; }
{TEXT}                                              { return STRING_TEXT; }

{WS}+                                               { /* whitespace separates tokens */ }

\n                                                  { return NEWLINE; }

.                                                   { /* discard bad characters */ }
<<eof>>                                             { return FLEX_EOF; }

%%
