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
        CLIENT_PLUGIN_AUTH = 0x00080000
    };

    class Packet {
    public:
        size_t payload_length;
        int sequence_id;
        std::string payload;

        void readHeader(std::string s) {
            payload_length = (*(uint32_t *) s.data()) & 0xffffff;
            sequence_id = *((uint8_t *) s.data() + 3);
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
            , capability_flags(CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
                | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | CLIENT_CONNECT_WITH_DB)
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

        std::string get_payload() {
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

        void read_payload(std::string& s) {
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

        std::string get_payload() {
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
}
