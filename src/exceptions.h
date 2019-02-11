//
// Created by Yuriy Baranov on 2019-02-11.
//
#pragma once

#ifndef PROJECT_EXCEPTIONS_H
#define PROJECT_EXCEPTIONS_H

#endif //PROJECT_EXCEPTIONS_H


class Error : public std::exception {
    std::string error;
public:
    explicit Error(const std::string& error) : error(error) {
    }
    const char* what() {
        return error.c_str();
    }
};

class NetError : public Error {
public:
    using Error::Error;
};

class ProtocolError : public Error {
public:
    using Error::Error;
};
