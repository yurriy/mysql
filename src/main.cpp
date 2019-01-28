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


class NetError : public std::exception {
    std::string error;
public:
    NetError(const std::string& error) : error(error) {
    }
    const char* what() {
        return error.c_str();
    }
};

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

    std::string toText(std::string packet) {
        std::string result;
        for (std::string::value_type c : packet) {
            result.append(std::to_string((unsigned char) c));
            result.append(1, ' ');
        }
        return result;
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

        Protocol::Packet packet;
        packet.readHeader(header);
        app.logger().information("parsed packet_length: " + std::to_string(packet.payload_length));
        app.logger().information("parsed sequence_id: " + std::to_string(packet.sequence_id));

        packet.payload.resize(packet.payload_length);
        receiveBuf(packet.payload.data(), packet.payload_length);

        app.logger().information(std::string("handshake response ") + toText(packet.payload));
        return packet;
    }

    void run()
    {
        app.logger().information("Request from " + this->socket().peerAddress().toString());
        try
        {
            Protocol::HandshakeV10 handshakeV10(connection_id);
            auto payload = handshakeV10.get_payload();
            std::string packet;
            int size = (int) payload.size();
            packet.append((const char *) &size, 3);
            packet.append(1, 0);  // sequence_id
            packet.append(payload);
            app.logger().information(std::string("packet: ") + toText(packet));
            sendBuf(packet.data(), packet.length());
            app.logger().information("sent handshake");

            auto handshake_response_packet = receivePacket();
            Protocol::HandshakeResponse41 handshakeResponse41;
            handshakeResponse41.read_payload(handshake_response_packet.payload);

            Protocol::OK_Packet ok_packet(0, handshakeResponse41.capability_flags, 0, 0, 0, "");
            payload = ok_packet.get_payload();
            size = (int) payload.size();

            packet.clear();
            packet.append((const char *) &size, 3);
            packet.append(1, 2);  // sequence_id
            packet.append(payload);
            app.logger().information(std::string("packet: ") + toText(packet));
            sendBuf(packet.data(), packet.length());
            app.logger().information("sent OK_Packet");
        }
        catch (Poco::Exception& exc)
        {
            app.logger().log(exc);
        }
    }

private:
    const uint32_t connection_id;
    Application& app;
};


class TimeServerConnectionFactory: public TCPServerConnectionFactory
    /// A factory for TimeServerConnection.
{
public:
    TimeServerConnectionFactory(const std::string& format):
        _format(format)
    {
    }

    TCPServerConnection* createConnection(const StreamSocket& socket)
    {
        return new MySQLServerConnection(socket, last_connection_id++);
    }

private:
    std::string _format;
    static uint32_t last_connection_id;
};

uint32_t TimeServerConnectionFactory::last_connection_id = 0;

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
            // get parameters from configuration file
            unsigned short port = (unsigned short) config().getInt("TimeServer.port", 9911);
            std::string format(config().getString("TimeServer.format", DateTimeFormat::ISO8601_FORMAT));

            // set-up a server socket
            ServerSocket svs(port);
            // set-up a TCPServer instance
            TCPServer srv(new TimeServerConnectionFactory(format), svs);
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
