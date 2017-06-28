QT = core network
TEMPLATE = app
SOURCES += main.cpp mitm.cpp
HEADERS += mitm.h

verbose {
  DEFINES += DEBUG
}
