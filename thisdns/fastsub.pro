TEMPLATE = app
CONFIG += console c++14
CONFIG -= app_bundle
CONFIG -= qt

INCLUDEPATH += $$PWD/third-party/include

SOURCES += \
    dns.cpp \
    DNSResolver.cpp \
    fastsub.cpp \
    uri.cpp

HEADERS += \
    ares_dns.hpp \
    dns.hpp \
    DNSResolver.hpp \
    uri.hpp

LIBS += -pthread
