#ifndef LOGGER_H
#define LOGGER_H

#define BRED "\033[41m"
#define BGRN "\033[42m"
#define BYEL "\033[43m"
#define BBLU "\033[44m"
#define BMGN "\033[45m"
#define BCYN "\033[46m"

#define  RED "\033[31m"
#define  GRN "\033[32m"
#define  YEL "\033[33m"
#define  BLU "\033[34m"
#define  MGN "\033[45m"
#define  CYN "\033[46m"

#define NOC "\033[0m"

void info       (const char *msg, ...);
void success    (const char *msg, ...);
void warn       (const char *msg, ...);
void err        (const char *msg, ...);

#endif
