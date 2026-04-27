#ifndef LOG_EXTRACT_H
#define LOG_EXTRACT_H

#define LOG_EXTRACT_VERSION "0.1.0"
#define LOG_EXTRACT_NAME    "log_extract"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #define PATH_SEP '\\'
    #define PATH_SEP_STR "\\"
#else
    #define PATH_SEP '/'
    #define PATH_SEP_STR "/"
#endif

#define MAX_PATH_LEN 1024
#define MAX_LINE_LEN 4096

/* Global verbosity — set by cli_parse, read by log_* macros */
extern int g_verbose;
extern int g_quiet;

#include "util.h"
#include "platform.h"
#include "filter.h"
#include "collector.h"
#include "cli.h"

#endif /* LOG_EXTRACT_H */
