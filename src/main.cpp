//
// TimeServer.cpp
//
// This sample demonstrates the TCPServer and ServerSocket classes.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/Net/TCPServer.h"
#include "Poco/Net/TCPServerConnection.h"
#include "Poco/Net/TCPServerConnectionFactory.h"
#include "Poco/Net/TCPServerParams.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Net/ServerSocket.h"
#include "Poco/Timestamp.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/DateTimeFormat.h"
#include "Poco/Exception.h"
#include "Poco/Util/ServerApplication.h"
#include "Poco/Util/Option.h"
#include "Poco/Util/OptionSet.h"
#include "Poco/Util/HelpFormatter.h"
#include <iostream>
#include <cstring>
#include "protocol.h"
#include "exceptions.h"

using Poco::Net::ServerSocket;
using Poco::Net::StreamSocket;
using Poco::Net::TCPServerConnection;
using Poco::Net::TCPServerConnectionFactory;
using Poco::Net::TCPServer;
using Poco::Timestamp;
using Poco::DateTimeFormatter;
using Poco::DateTimeFormat;
using Poco::Util::ServerApplication;
using Poco::Util::Application;
using Poco::Util::Option;
using Poco::Util::OptionSet;
using Poco::Util::HelpFormatter;




class MySQLServerConnection: public TCPServerConnection
    /// This class handles all client connections.
{
public:
    MySQLServerConnection(const StreamSocket& s, const uint32_t connection_id):
        TCPServerConnection(s),
        connection_id(connection_id),
        app(Application::instance())
    {
    }

    std::string toText(const std::string& packet) {
        std::string result;
        for (std::string::value_type c : packet) {
            result.append(std::to_string((unsigned char) c));
            result.append(1, ' ');
        }
        return result;
    }

    void sendStr(const std::string& s) {
        app.logger().information(std::string("send packet: ") + toText(s));
        sendBuf(s.data(), s.length());
    }

    void sendBuf(const char *buf, size_t size) {
        int cur = 0;
        while (cur != size) {
            int res = socket().sendBytes(buf + cur, (int) size);
            if (res == -1) {
                throw NetError(std::string("error on send: ") + strerror(errno) + " cur: " + std::to_string(cur));
            }
            app.logger().information(std::string("sent ") + std::to_string(res) + " bytes");
            cur += res;
        }
    }

    void receiveBuf(char *buf, size_t size) {
        int cur = 0;
        while (cur != size) {
            int res = socket().receiveBytes(buf + cur, (int) (size - cur));
            if (res == -1) {
                throw NetError(std::string("error on receive: ") + strerror(errno) + " cur: " + std::to_string(cur));
            }
            else if (res == 0) {
                throw NetError("unexpected end of stream");
            }
            cur += res;
            app.logger().information(std::string("received ") + std::to_string(res) + " bytes");
        }
    }

    Protocol::Packet receivePacket() {
        std::string header;
        header.resize(4);
        receiveBuf(header.data(), header.length());

        Protocol::Packet packet(header);
        app.logger().information("parsed packet_length: " + std::to_string(packet.payload_length));
        app.logger().information("parsed sequence_id: " + std::to_string(packet.sequence_id));

        packet.allocatePayload();
        receiveBuf(packet.getPayload().data(), packet.getPayloadLength());

        app.logger().information(std::string("payload ") + toText(packet.getPayload()));
        return packet;
    }

    void run()
    {
        app.logger().information("Request from " + this->socket().peerAddress().toString());
        try
        {
            Protocol::HandshakeV10 handshakeV10(connection_id);
            auto payload = handshakeV10.getPayload();
            Protocol::Packet packet(0, payload);
            sendStr(packet.toString());
            app.logger().information("sent handshake");

            auto handshake_response_packet = receivePacket();
            Protocol::HandshakeResponse41 handshakeResponse41;
            handshakeResponse41.readPayload(handshake_response_packet.payload);
            capabilities = handshakeResponse41.capability_flags;

            Protocol::OK_Packet ok_packet(0, handshakeResponse41.capability_flags, 0, 0, 0, "");
            payload = ok_packet.getPayload();
            packet = Protocol::Packet(2, payload);
            sendStr(packet.toString());
            app.logger().information("sent OK_Packet");

            while (true) {
                auto p = receivePacket();
                sequence_id = p.sequence_id + 1;
                app.logger().information(std::string("received command: ") + std::to_string(p.getCommandByte()));
                switch (p.getCommandByte()) {
                    case Protocol::COM_QUIT:
                        app.logger().information(std::string("client ") + std::to_string(connection_id) + " quited");
                        return;
                    case Protocol::COM_QUERY:
                        executeQuery(p);
                        break;
                    case Protocol::COM_FIELD_LIST:
                        sendFieldsList();
                        break;
                    case Protocol::COM_PING:
                        respondPing();
                        break;
                    default:
                        app.logger().error(std::string("Cannot handle command: ") + std::to_string(p.getCommandByte()));
                        return;
                }
            }
        }
        catch (Poco::Exception& exc)
        {
            app.logger().log(exc);
        }
    }

    void sendFieldsList() {

        Protocol::ColumnDefinition41 column1(
            "schema", "table", "table", "name", "name",
            63, 100, Protocol::ColumnType::MYSQL_TYPE_STRING, 0, 0);
        Protocol::ColumnDefinition41 column2(
            "schema", "table", "table", "index", "index",
            63, 8, Protocol::ColumnType::MYSQL_TYPE_LONG, 0, 0);

        sendStr(Protocol::Packet(sequence_id++, column1.getPayload()).toString());
        sendStr(Protocol::Packet(sequence_id++, column2.getPayload()).toString());

        sendStr(Protocol::Packet(sequence_id++, Protocol::EOF_Packet(0, 0).getPayload()).toString());

    }

    void respondPing() {
        sendStr(Protocol::Packet(sequence_id++, Protocol::OK_Packet(0x0, capabilities, 0, 0, 0, "").getPayload()).toString());
    }

    void sendResultSet() {

        size_t column_count = 2;
        Protocol::Packet packet(sequence_id++, Protocol::write_lenenc(column_count));
        sendStr(packet.toString());

        Protocol::ColumnDefinition41 column1(
            "schema", "table", "table", "name", "name",
            63, 100, Protocol::ColumnType::MYSQL_TYPE_STRING, 0, 0);
        Protocol::ColumnDefinition41 column2(
            "schema", "table", "table", "index", "index",
            63, 8, Protocol::ColumnType::MYSQL_TYPE_LONG, 0, 0);

        sendStr(Protocol::Packet(sequence_id++, column1.getPayload()).toString());
        sendStr(Protocol::Packet(sequence_id++, column2.getPayload()).toString());

        if (!(capabilities & Protocol::CLIENT_DEPRECATE_EOF)) {
            sendStr(Protocol::Packet(sequence_id++, Protocol::EOF_Packet(0, 0).getPayload()).toString());
        }

        std::string row1, row2;
        Protocol::write_lenenc_str(row1, "user1");
        Protocol::write_lenenc_str(row1, "100");
        Protocol::write_lenenc_str(row2, "user2");
        Protocol::write_lenenc_str(row2, "200");

        sendStr(Protocol::Packet(sequence_id++, row1).toString());
        sendStr(Protocol::Packet(sequence_id++, row2).toString());

        std::string payload;
        if (capabilities & Protocol::CLIENT_DEPRECATE_EOF) {
            sendStr(Protocol::Packet(sequence_id++, Protocol::OK_Packet(0xfe, capabilities, 0, 0, 0, "").getPayload()).toString());
        } else {
            sendStr(Protocol::Packet(sequence_id++, Protocol::EOF_Packet(0, 0).getPayload()).toString());
        }
    }

    void executeQuery(Protocol::Packet& packet) {
        app.logger().information(std::string("executing query: ") + packet.getPayload().substr(1));
        sendResultSet();
    }

private:
    const uint32_t connection_id;
    uint32_t capabilities;
    int sequence_id = 0;
    Application& app;
};


class MySQLServerConnectionFactory: public TCPServerConnectionFactory
    /// A factory for TimeServerConnection.
{
public:
    MySQLServerConnectionFactory() {
    }

    TCPServerConnection* createConnection(const StreamSocket& socket) override
    {
        return new MySQLServerConnection(socket, last_connection_id++);
    }

private:
    static uint32_t last_connection_id;
};

uint32_t MySQLServerConnectionFactory::last_connection_id = 0;

class TimeServer: public Poco::Util::ServerApplication
    /// The main application class.
    ///
    /// This class handles command-line arguments and
    /// configuration files.
    /// Start the TimeServer executable with the help
    /// option (/help on Windows, --help on Unix) for
    /// the available command line options.
    ///
    /// To use the sample configuration file (TimeServer.properties),
    /// copy the file to the directory where the TimeServer executable
    /// resides. If you start the debug version of the TimeServer
    /// (TimeServerd[.exe]), you must also create a copy of the configuration
    /// file named TimeServerd.properties. In the configuration file, you
    /// can specify the port on which the server is listening (default
    /// 9911) and the format of the date/time string sent back to the client.
    ///
    /// To test the TimeServer you can use any telnet client (telnet localhost 9911).
{
public:
    TimeServer(): _helpRequested(false)
    {
    }

    ~TimeServer()
    {
    }

protected:
    void initialize(Application& self)
    {
        loadConfiguration(); // load default configuration files, if present
        ServerApplication::initialize(self);
    }

    void uninitialize()
    {
        ServerApplication::uninitialize();
    }

    void defineOptions(OptionSet& options)
    {
        ServerApplication::defineOptions(options);

        options.addOption(
            Option("help", "h", "display help information on command line arguments")
                .required(false)
                .repeatable(false));
    }

    void handleOption(const std::string& name, const std::string& value)
    {
        ServerApplication::handleOption(name, value);

        if (name == "help")
            _helpRequested = true;
    }

    void displayHelp()
    {
        HelpFormatter helpFormatter(options());
        helpFormatter.setCommand(commandName());
        helpFormatter.setUsage("OPTIONS");
        helpFormatter.setHeader("A server application that serves the current date and time.");
        helpFormatter.format(std::cout);
    }

    int main(const std::vector<std::string>& args)
    {
        if (_helpRequested)
        {
            displayHelp();
        }
        else
        {
            // set-up a TCPServer instance
            TCPServer srv(new MySQLServerConnectionFactory(), Poco::Net::SocketAddress("ocelot.search.yandex.net", 9911));
            // start the TCPServer
            srv.start();
            // wait for CTRL-C or kill
            waitForTerminationRequest();
            // Stop the TCPServer
            srv.stop();
        }
        return Application::EXIT_OK;
    }

private:
    bool _helpRequested;
};


int main(int argc, char** argv)
{
    TimeServer app;
    return app.run(argc, argv);
}
