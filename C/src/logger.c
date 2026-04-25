#include <stdio.h>
#include <stdarg.h>

#include "../include/logger.h"

bool g_debug = false;
void logger_set_debug(bool on) { g_debug = on; }

void info(const char *msg, ...) {
        if (!g_debug) return;
        va_list args;
        va_start(args, msg);

        printf(BBLU "[i]" NOC " ");
        vprintf(msg, args);

        va_end(args);
}

void warn(const char *msg, ...) {
        if (!g_debug) return;
        va_list args;
        va_start(args, msg);

        printf(BYEL "[!]" NOC " ");
        vprintf(msg, args);

        va_end(args);
}

void success(const char *msg, ...) {
        va_list args;
        va_start(args, msg);

        printf(BGRN "[✓]" NOC " ");
        vprintf(msg, args);

        va_end(args);
}

void err(const char *msg, ...) {
        if (!g_debug) return;
        va_list args;
        va_start(args, msg);

        fprintf(stderr, BRED "[x]" NOC " ");
        vprintf(msg, args);

        va_end(args);
}
