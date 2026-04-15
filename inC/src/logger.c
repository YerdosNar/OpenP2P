#include <stdio.h>
#include <stdarg.h>

#include "../include/logger.h"

/*
 * Each log function now uses flockfile/funlockfile so that the prefix
 * and the message body are printed atomically, preventing interleaved
 * output from concurrent threads.
 */

void info(const char *msg, ...) {
        va_list args;
        va_start(args, msg);

        flockfile(stdout);
        fprintf(stdout, BBLU "[i]" NOC " ");
        vfprintf(stdout, msg, args);
        funlockfile(stdout);

        va_end(args);
}

void warn(const char *msg, ...) {
        va_list args;
        va_start(args, msg);

        flockfile(stdout);
        fprintf(stdout, BYEL "[!]" NOC " ");
        vfprintf(stdout, msg, args);
        funlockfile(stdout);

        va_end(args);
}

void success(const char *msg, ...) {
        va_list args;
        va_start(args, msg);

        flockfile(stdout);
        fprintf(stdout, BGRN "[✓]" NOC " ");
        vfprintf(stdout, msg, args);
        funlockfile(stdout);

        va_end(args);
}

void err(const char *msg, ...) {
        va_list args;
        va_start(args, msg);

        flockfile(stderr);
        fprintf(stderr, BRED "[x]" NOC " ");
        vfprintf(stderr, msg, args);
        funlockfile(stderr);

        va_end(args);
}
