QT = core network
TEMPLATE = app
SOURCES += main.cpp mitm.cpp
HEADERS += mitm.h

CONFIG(debug, debug|release): DEFINES += DEBUG
