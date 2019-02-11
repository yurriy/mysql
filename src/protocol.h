//
// Created by Yuriy Baranov on 2019-01-20.
//

#ifndef PROJECT_PROTOCOL_H
#define PROJECT_PROTOCOL_H

#endif //PROJECT_PROTOCOL_H

#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <streambuf>
#include <sstream>
#include <cstdint>

#include "Poco/Util/Application.h"
#include "basic_types.h"
#include "exceptions.h"

#define SCRAMBLE_LENGTH 20
#define AUTH_PLUGIN_DATA_PART_1_LENGTH 8

namespace Protocol {

    namespace Authentication {
        const std::string Native41 = "mysql_native_password";
    }
    enum StatusFlags {
        SERVER_SESSION_STATE_CHANGED = 0x4000
    };

    enum Capability {
        CLIENT_CONNECT_WITH_DB = 0x00000008,
        CLIENT_PROTOCOL_41 = 0x00000200,
        CLIENT_TRANSACTIONS = 0x00002000, // TODO
        CLIENT_SESSION_TRACK = 0x00800000, // TODO
        CLIENT_SECURE_CONNECTION = 0x00008000,
        CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000,
        CLIENT_PLUGIN_AUTH = 0x00080000,
        CLIENT_DEPRECATE_EOF = 0x01000000,
    };

    enum Command {
        COM_SLEEP = 0x0,
        COM_QUIT = 0x1,
        COM_INIT_DB = 0x2,
        COM_QUERY = 0x3,
        COM_FIELD_LIST = 0x4,
        COM_CREATE_DB = 0x5,
        COM_DROP_DB = 0x6,
        COM_REFRESH = 0x7,
        COM_SHUTDOWN = 0x8,
        COM_STATISTICS = 0x9,
        COM_PROCESS_INFO = 0xa,
        COM_CONNECT = 0xb,
        COM_PROCESS_KILL = 0xc,
        COM_DEBUG = 0xd,
        COM_PING = 0xe,
        COM_TIME = 0xf,
        COM_DELAYED_INSERT = 0x10,
        COM_CHANGE_USER = 0x11,
        COM_RESET_CONNECTION = 0x1f,
        COM_DAEMON = 0x1d
    };

    enum ColumnType {
         MYSQL_TYPE_DECIMAL = 0x00,
         MYSQL_TYPE_TINY = 0x01,
         MYSQL_TYPE_SHORT = 0x02,
         MYSQL_TYPE_LONG = 0x03,
         MYSQL_TYPE_FLOAT = 0x04,
         MYSQL_TYPE_DOUBLE = 0x05,
         MYSQL_TYPE_NULL = 0x06,
         MYSQL_TYPE_TIMESTAMP = 0x07,
         MYSQL_TYPE_LONGLONG = 0x08,
         MYSQL_TYPE_INT24 = 0x09,
         MYSQL_TYPE_DATE = 0x0a,
         MYSQL_TYPE_TIME = 0x0b,
         MYSQL_TYPE_DATETIME = 0x0c,
         MYSQL_TYPE_YEAR = 0x0d,
         MYSQL_TYPE_VARCHAR = 0x0f,
         MYSQL_TYPE_BIT = 0x10,
         MYSQL_TYPE_NEWDECIMAL = 0xf6,
         MYSQL_TYPE_ENUM = 0xf7,
         MYSQL_TYPE_SET = 0xf8,
         MYSQL_TYPE_TINY_BLOB = 0xf9,
         MYSQL_TYPE_MEDIUM_BLOB = 0xfa,
         MYSQL_TYPE_LONG_BLOB = 0xfb,
         MYSQL_TYPE_BLOB = 0xfc,
         MYSQL_TYPE_VAR_STRING = 0xfd,
         MYSQL_TYPE_STRING = 0xfe,
         MYSQL_TYPE_GEOMETRY = 0xff
    };

    class Packet {
    public:
        size_t payload_length;
        int sequence_id;
        std::string payload;

        Packet(int sequence_id, const std::string& payload)
            : sequence_id(sequence_id)
            , payload(payload)
            , payload_length(payload.length()) {
        }

        explicit Packet(std::string& header) {
            payload_length = (*(uint32_t *) header.data()) & 0xffffff;
            sequence_id = *((uint8_t *) header.data() + 3);
        }

        void allocatePayload() {
            payload.resize(payload_length);
        }

        std::string& getPayload() {
            return payload;
        }

        size_t getPayloadLength() {
            return payload_length;
        }

        int getCommandByte() {
            if (payload.length() == 0) {
                throw ProtocolError("payload is empty, cannot get command byte");
            }
            return (int) payload[0];
        }

        std::string toString() {
            std::string result;
            result.append((const char *) &payload_length, 3);
            result.append((const char *) &sequence_id, 1);
            result.append(payload);
            return result;
        }
    };

    class HandshakeV10 {
        int protocol_version = 0xa;
        std::string server_version;
        uint32_t connection_id;
        uint32_t capability_flags;
        uint8_t character_set;
        uint32_t status_flags;
        std::string auth_plugin_data;
    public:
        explicit HandshakeV10(uint32_t connection_id)
            : protocol_version(0xa)
            , server_version("1")
            , connection_id(connection_id)
            , capability_flags(
                CLIENT_PROTOCOL_41
                | CLIENT_SECURE_CONNECTION
                | CLIENT_PLUGIN_AUTH
                | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
                | CLIENT_CONNECT_WITH_DB
                | CLIENT_DEPRECATE_EOF)
            , character_set(63)
            , status_flags(0) {
            auth_plugin_data.resize(SCRAMBLE_LENGTH);

            auto seed = std::chrono::system_clock::now().time_since_epoch().count();
            std::default_random_engine generator ((unsigned int) seed);

            std::uniform_int_distribution<char> distribution(0);
            for (int i = 0; i < SCRAMBLE_LENGTH; i++) {
                auth_plugin_data[i] = distribution(generator);
            }
        }

        std::string getPayload() {
            std::string result;
            result.append(1, protocol_version);
            result.append(server_version);
            result.append(1, 0x0);
            result.append((const char *) &connection_id, 4);
            result.append(auth_plugin_data.substr(0, AUTH_PLUGIN_DATA_PART_1_LENGTH));
            result.append(1, 0x0);
            result.append((const char *) &capability_flags, 2);
            result.append((const char *) &character_set, 1);
            result.append((const char *) &status_flags, 2);
            result.append(((const char *) &capability_flags) + 2, 2);
            result.append(1, SCRAMBLE_LENGTH + 1);
            result.append(1, 0x0);
            result.append(10, 0x0);
            result.append(auth_plugin_data.substr(AUTH_PLUGIN_DATA_PART_1_LENGTH, SCRAMBLE_LENGTH - AUTH_PLUGIN_DATA_PART_1_LENGTH));
            result.append(Authentication::Native41);
            result.append(1, 0x0);
            return result;
        }
    };

    class HandshakeResponse41 {
    public:
        uint32_t capability_flags;
        uint32_t max_packet_size;
        uint8_t character_set;
        std::string username;
        std::string auth_response;
        std::string database;
        std::string auth_plugin_name;

        void readPayload(std::string &s) {
            auto& logger = Poco::Util::Application::instance().logger();
            std::istringstream ss(s);
            ss.readsome((char *) &capability_flags, 4);
            ss.readsome((char *) &max_packet_size, 4);
            ss.readsome((char *) &character_set, 1);
            ss.ignore(23);

            std::getline(ss, username, (char) 0x0);

            if (capability_flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
                auto len = read_lenenc(ss);
                logger.information(std::string("auth response length: ") + std::to_string(len));
                auth_response.resize(len);
                ss.read(auth_response.data(), (std::streamsize) len);
            } else if (capability_flags & CLIENT_SECURE_CONNECTION) {
                uint8_t len;
                ss.read((char *) &len, 1);
                auth_response.resize(len);
                ss.read(auth_response.data(), (std::streamsize) len);
            } else {
                std::getline(ss, auth_response, (char) 0x0);
            }

            if (capability_flags & CLIENT_CONNECT_WITH_DB) {
                std::getline(ss, database, (char) 0x0);
            }

            if (capability_flags & CLIENT_PLUGIN_AUTH) {
                std::getline(ss, auth_plugin_name, (char) 0x0);
            }

            logger.information(std::string("capability_flags: " + std::to_string(capability_flags)));
            logger.information(std::string("max_packet_size: " + std::to_string(max_packet_size)));
            logger.information(std::string("character_set: " + std::to_string(character_set)));
            logger.information(std::string("user: " + username));
            logger.information(std::string("auth_response length: " + std::to_string(auth_response.length())));
            logger.information(std::string("auth_response: " + auth_response));
            logger.information(std::string("database: " + database));
            logger.information(std::string("auth_plugin_name: " + auth_plugin_name));

        }
    };

    class OK_Packet {
        uint8_t header;
        uint64_t affected_rows;
        uint64_t last_insert_id;
        uint32_t status_flags;
        int16_t warnings;
        std::string info;
        std::string session_state_changes;
        uint32_t capabilities;
    public:
        OK_Packet(uint8_t header, uint32_t capabilities, uint64_t affected_rows, uint64_t last_insert_id, uint32_t status_flags,
            const std::string& session_state_changes)
            : header(header), capabilities(capabilities), affected_rows(affected_rows), last_insert_id(last_insert_id)
            , status_flags(status_flags), session_state_changes(session_state_changes)
        {
        }

        std::string getPayload() {
            std::string result;
            result.append(1, header);
            result.append(write_lenenc(affected_rows));
            result.append(write_lenenc(last_insert_id));

            if (capabilities & CLIENT_PROTOCOL_41) {
                result.append((const char *) &status_flags, 2);
                result.append((const char *) &warnings, 2);
            } else if (capabilities & CLIENT_TRANSACTIONS) {
                result.append((const char *) &status_flags, 2);
            }

            if (capabilities & CLIENT_SESSION_TRACK) {
                result.append(write_lenenc(info.length()));
                result.append(info);
                if (status_flags & SERVER_SESSION_STATE_CHANGED) {
                    result.append(write_lenenc(session_state_changes.length()));
                    result.append(session_state_changes);
                }
            } else {
                result.append(info);
            }
            return result;
        }
    };

    class EOF_Packet {
        int warnings;
        int status_flags;
    public:
        EOF_Packet(int warnings, int status_flags): warnings(warnings), status_flags(status_flags) {}

        std::string getPayload() {
            std::string result;
            result.append(1, 0xfe); // EOF header
            result.append((const char *) &warnings, 2);
            result.append((const char *) &status_flags, 2);
            return result;
        }
    };

    class ColumnDefinition41 {
        std::string schema;
        std::string table;
        std::string org_table;
        std::string name;
        std::string org_name;
        size_t next_length = 0x0c;
        uint16_t character_set;
        uint32_t column_length;
        ColumnType column_type;
        uint16_t flags;
        uint8_t decimals = 0x00;
    public:
        explicit ColumnDefinition41(
            const std::string& schema,
            const std::string& table,
            const std::string& org_table,
            const std::string& name,
            const std::string& org_name,
            uint16_t character_set,
            uint32_t column_length,
            ColumnType column_type,
            uint16_t flags,
            uint8_t decimals)

            : schema(schema)
            , table(table)
            , org_table(org_table)
            , name(name)
            , org_name(org_name)
            , character_set(character_set)
            , column_length(column_length)
            , column_type(column_type)
            , flags(flags)
            , decimals(decimals)
            {
        }

        std::string getPayload() {
            std::string result;
            write_lenenc_str(result, "def"); // always "def"
            write_lenenc_str(result, schema);
            write_lenenc_str(result, table);
            write_lenenc_str(result, org_table);
            write_lenenc_str(result, name);
            write_lenenc_str(result, org_name);
            result.append(write_lenenc(next_length));
            result.append((const char *) &character_set, 2);
            result.append((const char *) &column_length, 4);
            result.append((const char *) &column_type, 1);
            result.append((const char *) &flags, 2);
            result.append((const char *) &decimals, 2);
            result.append(2, 0x0);
            return result;
        }
    };
}
