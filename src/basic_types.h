//
// Created by Yuriy Baranov on 2019-01-28.
//

#ifndef PROJECT_BASIC_TYPES_H
#define PROJECT_BASIC_TYPES_H

#endif //PROJECT_BASIC_TYPES_H

#include <sstream>
#include <cstdint>

namespace Protocol {

    uint64_t read_lenenc(std::istringstream& ss) {
        char c;
        ss.get(c);
        auto cc = (uint8_t) c;
        if (cc < 0xfc) {
            return cc;
        } else if (cc < 0xfd) {
            char buf[2];
            ss.read(buf, 2);
            return *(uint16_t *) buf;
        } else if (cc < 0xfe) {
            char buf[4];
            buf[3] = 0;
            ss.read(buf, 3);
            return *(uint32_t *) buf;
        } else {
            char buf[8];
            ss.read(buf, 8);
            return *(uint64_t *) buf;
        }
    }

    std::string write_lenenc(uint64_t x) {
        std::string result;
        if (x < 251) {
            result.append(1, (char) x);
        } else if (x < (1 << 16)) {
            result.append(1, 0xfc);
            result.append((char *) &x, 2);
        } else if (x < (1 << 24)) {
            result.append(1, 0xfd);
            result.append((char *) &x, 3);
        } else {
            result.append(1, 0xfe);
            result.append((char *) &x, 8);
        }
        return result;
    }
}
