#ifndef MSGTYPE_H
#define MSGTYPE_H

#include <stdint.h>

typedef enum {
        MSG_CHAT        = 0x01,
        FILE_OFFER      = 0x02,
        FILE_ACCEPT     = 0x03,
        FILE_REJECT     = 0x04,
        FILE_CHUNK      = 0x05,
        FILE_EOF        = 0x06
} MsgType;

#endif
