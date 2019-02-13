%require "3.0"

%code requires{
#include "config_file.h"
#include "bison_parser.h"
}

%union{
  long long number;
  char* text;
};

%token KW_NAMESERVER KW_PARALLEL_QUERY KW_CACHE_COUNT
%token KW_LOG KW_LOG_FILE KW_DEFAULT_TTL
%token KW_RE_QUERY KW_SERVER KW_REPORT_TIMEOUT
%token KW_ON KW_OFF
%token KW_LOG_TRACE KW_LOG_ERROR KW_LOG_WARNING KW_LOG_INFO

%token <number> NUMBER
%token <text> IP
%token <text> STRING_TEXT
%token <text> DOMAIN

%token END 0
%token NEWLINE

%start conf_file

%%

conf_file
      : conf_line
      | conf_file conf_line

conf_line
      : nameserver_line
      | parallel_line
      | cachecount_line
      | log_line
      | log_file_line
      | ttl_line
      | timeout_requery
      | static_server
      | report_line
      | NEWLINE

report_line
      : KW_REPORT_TIMEOUT NUMBER NEWLINE          { config_set_report_timeout($2); }

nameserver_line
      : KW_NAMESERVER IP NEWLINE                  { config_add_nameserver($2); free($2); }


parallel_line
      : KW_PARALLEL_QUERY KW_ON  NEWLINE          { config_set_parallel_query(VALUE_ON); }
      | KW_PARALLEL_QUERY KW_OFF NEWLINE          { config_set_parallel_query(VALUE_OFF); }

cachecount_line
      : KW_CACHE_COUNT NUMBER NEWLINE             { config_set_cache_count($2); }


log_line
      : KW_LOG KW_LOG_TRACE NEWLINE               { config_set_log_level(LOG_TRACE); }
      | KW_LOG KW_LOG_WARNING NEWLINE             { config_set_log_level(LOG_WARNING); }
      | KW_LOG KW_LOG_ERROR NEWLINE               { config_set_log_level(LOG_ERROR); }
      | KW_LOG KW_LOG_INFO NEWLINE                { config_set_log_level(LOG_INFO); }
      | KW_LOG KW_OFF NEWLINE                     { config_set_log_level(LOG_OFF); }

log_file_line
      : KW_LOG_FILE STRING_TEXT NEWLINE           { config_set_log_file($2); free($2); }

ttl_line
      : KW_DEFAULT_TTL NUMBER NEWLINE             { config_set_default_ttl($2); }

timeout_requery
      : KW_RE_QUERY KW_ON NEWLINE                 { config_set_requery(VALUE_ON); }
      | KW_RE_QUERY KW_OFF NEWLINE                { config_set_requery(VALUE_OFF); }

static_server
      : KW_SERVER DOMAIN IP NEWLINE               { config_add_static_ip($2, $3);free($2);free($3); }

%%

