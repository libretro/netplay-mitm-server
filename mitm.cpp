/*  netplay-mitm-server - A man-in-the-middle server implementation for RetroArch netplay.
 *  Copyright (C) 2017 - Brad Parker
 *
 *  netplay-mitm-server is free software: you can redistribute it and/or modify it under the terms
 *  of the GNU General Public License as published by the Free Software Found-
 *  ation, either version 3 of the License, or (at your option) any later version.
 *
 *  netplay-mitm-server is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 *  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 *  PURPOSE.  See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along with netplay-mitm-server.
 *  If not, see <http://www.gnu.org/licenses/>.
 */

#include "mitm.h"
#include <stdio.h>

#ifdef Q_OS_UNIX
#include <signal.h>
#endif

#include <arpa/inet.h>

#ifdef DEBUG
static QString getPeerIPv4(QHostAddress addr) {
  struct in_addr ip_addr;

  ip_addr.s_addr = addr.toIPv4Address();

  return QString(inet_ntoa(ip_addr));
}

#define QC_STR(x) x.toStdString().c_str()
#define HOST(x) getPeerIPv4(x->peerAddress())
#define PORT(x) x->peerPort()
#define CLIENT_LOG(x, y) printf("%s:%d %s\n", QC_STR(HOST(x)), PORT(x), y)
#define CLIENT_LOGF(x, fmt, ...) printf("%s:%d ", QC_STR(HOST(x)), PORT(x)); printf(fmt, __VA_ARGS__)

#if DEBUG == 2
#define CLIENT_LOG2(x, y) CLIENT_LOG(x, y)
#define CLIENT_LOGF2(x, fmt, ...) CLIENT_LOGF(x, fmt, __VA_ARGS__)
#else
#define CLIENT_LOG2(x, y)
#define CLIENT_LOGF2(x, fmt, ...)
#endif

#else
#define CLIENT_LOG(x, y)
#define CLIENT_LOG2(x, y)
#define CLIENT_LOGF(x, fmt, ...)
#define CLIENT_LOGF2(x, fmt, ...)
#endif

#define PORT_EXPIRE_TIMEOUT_SECS 3600

size_t strlcpy(char *dest, const char *source, size_t size)
{
  size_t src_size = 0;
  size_t n = size;

  if(n)
    while(--n && (*dest++ = *source++)) src_size++;

  if(!n) {
    if(size) *dest = '\0';
    while(*source++) src_size++;
  }

  return src_size;
}

static void dump_uints(const char *data, int bytes) {
#if DEBUG == 2
  for(uint i = 0; i < bytes / sizeof(uint32_t); i++) {
    printf(" %08X", ntohl(((uint32_t*)data)[i]));
  }

  printf("\n");
#else
  Q_UNUSED(data)
  Q_UNUSED(bytes)
#endif
}

MITM::MITM(QObject *parent) :
  QObject(parent)
  ,m_server(new QTcpServer(this))
  ,m_servers()
  ,m_getopt()
  ,m_timer()
{
#ifdef Q_OS_UNIX
  struct sigaction sigint, sigterm;

  sigint.sa_handler = MITM::handleSIGINT;
  sigemptyset(&sigint.sa_mask);
  sigint.sa_flags = 0;
  sigint.sa_flags |= SA_RESTART;

  sigaction(SIGINT, &sigint, 0);

  sigterm.sa_handler = MITM::handleSIGTERM;
  sigemptyset(&sigterm.sa_mask);
  sigterm.sa_flags = 0;
  sigterm.sa_flags |= SA_RESTART;

  sigaction(SIGTERM, &sigterm, 0);
#endif

  m_getopt.setApplicationDescription("Netplay man-in-the-middle server for RetroArch");
  m_getopt.addHelpOption();
  m_getopt.addVersionOption();
  m_getopt.addOption(QCommandLineOption(QStringList() << "p" << "port", "Port to listen on, default is 55435.", "port"));
  m_getopt.addOption(QCommandLineOption(QStringList() << "m" << "multi", "Multi-server mode. The main port becomes a command interface used to request new ports to be added. Send CMD_REQ_PORT to add a new server."));
  m_getopt.process(*qApp);

  connect(m_server.data(), SIGNAL(acceptError(QAbstractSocket::SocketError)), this, SLOT(acceptError(QAbstractSocket::SocketError)));
  connect(m_server.data(), SIGNAL(newConnection()), this, SLOT(newConnection()));
  connect(&m_timer, SIGNAL(timeout()), this, SLOT(timeout()));

  m_server->setProperty("master", true);

  Server s;
  s.server = m_server;

  m_servers.append(s);
}

void MITM::sendMODE(QTcpSocket *sock) {
  union {
    mode_buf_pre5_s mode_pre5;
    mode_buf_s mode;
  };

  size_t mode_size;
  const Server &server_s = m_servers.at(sock->property("server").toInt());

  if(server_s.version >= NETPLAY_VERSION_INPUT_UPGRADE)
    mode_size = sizeof(mode);
  else
    mode_size = sizeof(mode_pre5);

  memset(&mode_pre5, 0, mode_size);

  mode.cmd[0] = htonl(CMD_MODE);
  mode.cmd[1] = htonl(mode_size - sizeof(mode_pre5.cmd));

  const QPointer<QTcpServer> &server = server_s.server;
  const QList<QPointer<QTcpSocket> > &sockets = server_s.sockets;

  if(sockets.count() == 0 || !server)
    return;

  uint frameNumber = server->property("frame_count").toUInt();

  mode.frame_num = htonl(frameNumber);

  if(server_s.version >= NETPLAY_VERSION_INPUT_UPGRADE) {
    mode.client_num = htons(sockets.indexOf(sock) + 1);
    mode.devices = htonl(1U << sockets.indexOf(sock));
  }else{
    mode_pre5.player_num = htons(sockets.indexOf(sock));
  }

  for(int i = 0; i < sockets.count(); ++i) {
    const QPointer<QTcpSocket> &player = sockets.at(i);

    if(!player)
      continue;

    if(!player->property("sync_sent").toBool()) {
      // don't send MODE to other players that haven't finished their handshake yet
      continue;
    }

    if(server_s.version >= NETPLAY_VERSION_INPUT_UPGRADE) {
      if(player == sock) {
        mode.target = htons(1U << 15 | 1U << 14);
      }else{
        mode.target = htons(1U << 14);
      }
    }else{
      if(player == sock) {
        mode.target = htons(3); // bit0 == is MODE being sent to the affected player, bit1 == is the user now playing or spectating
      }else{
        mode.target = htons(2);
      }
    }

    CLIENT_LOGF(sock, "MODE for player %d:", sockets.indexOf(player));
#ifdef DEBUG
    for(uint i = 0; i < sizeof(mode_pre5) / sizeof(uint32_t); ++i) {
      printf(" %08X", ntohl(((uint32_t*)&mode_pre5)[i]));
    }

    printf("\n");
#endif
    player->write((const char *)&mode, mode_size);
  }

  CLIENT_LOG(sock, "sent MODE to all users");
}

void MITM::start() {
  int port = 55435;

  if(m_getopt.isSet("port")) {
    port = m_getopt.value("port").toInt();
  }

  if(!m_server)
    return;

  if(!m_server->listen(QHostAddress::Any, port)) {
    printf("could not bind to port %d\n", port);
    QCoreApplication::quit();
    return;
  }

  printf("bound to port %d\n", m_server->serverPort());

  m_timer.start(PORT_EXPIRE_TIMEOUT_SECS * 1000);
}

void MITM::timeout() {
  printf("checking for expired ports...\n");

  QMutableListIterator<Server> i(m_servers);

  while(i.hasNext()) {
    Server &server = i.next();
    qint64 now = QDateTime::currentMSecsSinceEpoch() / 1000;
    qint64 last_updated = server.server->property("updated").toLongLong();

    if(now - last_updated > PORT_EXPIRE_TIMEOUT_SECS) {
      bool master = server.server->property("master").toBool();

      if(!master) {
        printf("expiring old port %d\n", server.server->serverPort());

        server.server->close();
        server.server->deleteLater();
        i.remove();
      }
    }
  }
}

void MITM::handleSIGINT(int) {
  printf("quitting...\n");
  QCoreApplication::quit();
}

void MITM::handleSIGTERM(int) {
  printf("quitting...\n");
  QCoreApplication::quit();
}

void MITM::acceptError(QAbstractSocket::SocketError socketError) {
  printf("got accept() error code %d\n", socketError);
}

void MITM::newConnection() {
  QTcpServer *server = qobject_cast<QTcpServer*>(sender());

  if(!server) {
    printf("could not find server for new connection\n");
    QCoreApplication::quit();
    return;
  }

  Server *server_ptr = NULL;
  int server_index = 0;

  // find Server associated with this QTcpServer
  for(int i = 0; i < m_servers.count(); ++i) {
    Server &s = m_servers[i];

    if(s.server == server) {
      server_ptr = &s;
      server_index = i;
      break;
    }
  }

  if(!server_ptr) {
    printf("could not find server instance for new connection\n");
    QCoreApplication::quit();
    return;
  }

  Server &server_s = *server_ptr;
  QTcpSocket *sock = server->nextPendingConnection();
  QList<QPointer<QTcpSocket> > &sockets = server_s.sockets;

  if(!sock) {
    printf("could not find socket for new connection\n");
    QCoreApplication::quit();
    return;
  }

  sockets.append(sock);

  qint64 epoch = QDateTime::currentMSecsSinceEpoch() / 1000;
  server->setProperty("updated", epoch);

  sock->setProperty("server", server_index);

  if(m_getopt.isSet("multi") && server == m_server)
    sock->setProperty("state", STATE_NONE);

  CLIENT_LOG(sock, "got new connection");

  connect(sock, SIGNAL(readyRead()), this, SLOT(readyRead()));
  connect(sock, SIGNAL(disconnected()), this, SLOT(disconnected()));
  connect(sock, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(error(QAbstractSocket::SocketError)));
}

void MITM::readyRead() {
  QTcpSocket *sock = qobject_cast<QTcpSocket*>(sender());

  if(!sock) {
    printf("ERROR: no socket in readyRead\n");
    return;
  }

  if(m_servers.count() == 0) {
    printf("ERROR: no servers\n");
    return;
  }

  int serverIndex = sock->property("server").toInt();

  if(serverIndex > m_servers.count() - 1) {
    printf("ERROR: server not found\n");
    return;
  }

  Server &server_s = m_servers[serverIndex];

  const QPointer<QTcpServer> &server = server_s.server;

  if(!server) {
    printf("ERROR: no server\n");
    return;
  }

  QList<QPointer<QTcpSocket> > &sockets = server_s.sockets;
  ClientState state = static_cast<ClientState>(sock->property("state").toUInt());
  uint32_t cmd[2] = {0};

  if(!server) {
    printf("ERROR: no server for socket\n");
    return;
  }

  //printf("readyRead: %lli bytes available, state is %d for host %s\n", sock->bytesAvailable(), state, QC_STR(sock->peerAddress().toString()));

  // check for end of mandatory state handling before accepting any new commands
  if(state >= STATE_NONE) {
    if(sock->bytesAvailable() < 8) {
      // wait for more data
      //printf("not enough data for a command yet, keep waiting\n");
      return;
    }

    // after the header we switch to a command-based format
    uint32_t newcmd[2];
    uint32_t current_cmd = sock->property("cmd").toUInt();
    uint32_t cmd_size = sock->property("cmd_size").toUInt();

    // only look for a new command if we're not currently waiting on more data
    if(cmd_size == 0) {
      qint64 readBytes = sock->read((char*)newcmd, 8);

      if(readBytes != 8) {
        CLIENT_LOG(sock, "invalid data received, aborting connection");
        sock->deleteLater();
        return;
      }
    }

    if(cmd_size > 0) {
      cmd[0] = current_cmd;
      cmd[1] = cmd_size;
    }else{
      cmd[0] = ntohl(newcmd[0]);
      cmd[1] = ntohl(newcmd[1]);
    }

    if(sock->bytesAvailable() < (qint64)cmd[1]) {
      //CLIENT_LOGF(sock, "WARNING: not enough data, we have %lli bytes available but the command payload size is %u\n", sock->bytesAvailable(), cmd[1]);
      sock->setProperty("cmd", cmd[0]);
      sock->setProperty("cmd_size", cmd[1]);
    }

    if(state == STATE_NONE) {
      if(cmd[0] == CMD_ACK) {
        CLIENT_LOG(sock, "ACK");
        // acknowledge, wait for next command
      }

      if(cmd[0] == CMD_NACK || cmd[0] == CMD_DISCONNECT) {
        CLIENT_LOG(sock, "client didn't like our data or requested a disconnect, aborting connection");
        sock->deleteLater();
        return;
      }

      switch(cmd[0]) {
        case CMD_NICK:
          state = STATE_RECV_NICKNAME;
          break;
        case CMD_INFO:
          state = STATE_RECV_INFO;
          break;
        case CMD_PLAY:
          state = STATE_RECV_PLAY;
          break;
        case CMD_INPUT:
          state = STATE_RECV_INPUT;
          break;
        case CMD_LOAD_SAVE:
          state = STATE_RECV_LOAD_SAVE;
          break;
        case CMD_REQ_PORT:
          state = STATE_RECV_REQ_PORT;
          break;
        default:
          break;
      }

      if(cmd[0] != CMD_INPUT && cmd_size == 0) {
        CLIENT_LOGF(sock, "got command %08X with payload size %u\n", cmd[0], cmd[1]);
      }
    }
  }

  switch(state) {
    case STATE_HEADER:
    {
      if(sockets.indexOf(sock) == 0) {
        if(sock->bytesAvailable() < HEADER_LEN) {
          // not enough data available yet, keep waiting
          CLIENT_LOGF(sock, "header: not enough data available, only %lli bytes out of %d\n", sock->bytesAvailable(), HEADER_LEN);
          return;
        }else{
          union {
            char header[HEADER_LEN];
            uint32_t headerMagic;
          };

          qint64 readBytes = sock->read(header, HEADER_LEN);

          if(readBytes != HEADER_LEN) {
            CLIENT_LOG(sock, "no header received, aborting connection");
            sock->deleteLater();
            return;
          }

          CLIENT_LOGF(sock, "header: got %lli bytes\n", readBytes);

          // check if it's a header for version >= 5
          if(ntohl(headerMagic) == NETPLAY_MAGIC) {
            server_s.version = NETPLAY_VERSION_INPUT_UPGRADE;
          }else{
            // We don't know the exact version, but all earlier versions are the same to us
            server_s.version = NETPLAY_VERSION_FIRST;
          }

          // store the first client's header to use for all others
          server->setProperty("header", QByteArray(header, HEADER_LEN));
        }
      }

      QByteArray server_header = server->property("header").toByteArray();

      // send header to client, we already have the first connection's header at this point
      qint64 wroteBytes = sock->write(server_header);

      if(wroteBytes != HEADER_LEN) {
        CLIENT_LOG(sock, "could not send header to client, aborting connection");
        sock->deleteLater();
        return;
      }else{
        CLIENT_LOG(sock, "sent header to client");
      }

      if(sockets.count() > 1) {
        // read connection header back and verify it is the same as the first client
        char header[HEADER_LEN];

        qint64 readBytes = sock->read(header, HEADER_LEN);

        if(readBytes != HEADER_LEN) {
          CLIENT_LOG(sock, "no header received, aborting connection");
          sock->deleteLater();
          return;
        }

        const char *server_header_data = server_header.constData();

        CLIENT_LOGF(sock, "SVR header: %08X %08X %08X %08X\n", ((uint*)server_header_data)[0], ((uint*)server_header_data)[1], ((uint*)server_header_data)[2], ((uint*)server_header_data)[3]);
        CLIENT_LOGF(sock, "CLT header: %08X %08X %08X %08X\n", ((uint*)header)[0], ((uint*)header)[1], ((uint*)header)[2], ((uint*)header)[3]);

        // word1 is the platform info, and they're allowed to be different, so don't check it
        bool word0 = memcmp(header + sizeof(uint32_t) * 0, server_header_data + sizeof(uint32_t) * 0, sizeof(uint32_t));
        //bool word1 = memcmp(header + sizeof(uint32_t) * 1, server_header_data + sizeof(uint32_t) * 1, sizeof(uint32_t));
        bool word2 = memcmp(header + sizeof(uint32_t) * 2, server_header_data + sizeof(uint32_t) * 2, sizeof(uint32_t));
        bool word3 = memcmp(header + sizeof(uint32_t) * 3, server_header_data + sizeof(uint32_t) * 3, sizeof(uint32_t));

        if(word0 || word2 || word3) {
          // header did not match the first connection
          CLIENT_LOG(sock, "header did not match the first connection, aborting");
          sock->deleteLater();
          return;
        }else{
          CLIENT_LOG(sock, "header matches");
        }
      }

      if(server_s.version >= NETPLAY_VERSION_INPUT_UPGRADE)
        sock->setProperty("state", STATE_POST_HEADER); // We still have more header
      else
        sock->setProperty("state", STATE_SEND_NICKNAME);

      break;
    }
    case STATE_POST_HEADER:
    {
      // FIXME: This code is almost identical to STATE_HEADER, can probably be refactored
      // FIXME 2: This reqiures exact match, but direct connections are now looser.
      if(sockets.indexOf(sock) == 0) {
        if(sock->bytesAvailable() < POST_HEADER_LEN) {
          // not enough data available yet, keep waiting
          CLIENT_LOGF(sock, "post header: not enough data available, only %lli bytes out of %d\n", sock->bytesAvailable(), POST_HEADER_LEN);
          return;
        }else{
          union {
            char header[POST_HEADER_LEN];
            uint32_t rawProtocolVersion;
          };

          uint32_t protocolVersion;

          qint64 readBytes = sock->read(header, POST_HEADER_LEN);

          if(readBytes != POST_HEADER_LEN) {
            CLIENT_LOG(sock, "no header received, aborting connection");
            sock->deleteLater();
            return;
          }

          CLIENT_LOGF(sock, "post header: got %lli bytes\n", readBytes);

          // check if it's a header for version >= 5
          protocolVersion = ntohl(rawProtocolVersion);

          if(protocolVersion >= NETPLAY_VERSION_INPUT_UPGRADE && protocolVersion <= NETPLAY_VERSION_LAST)
            server_s.version = protocolVersion;

          // store the first client's header to use for all others
          server->setProperty("post_header", QByteArray(header, POST_HEADER_LEN));
        }
      }

      QByteArray server_header = server->property("post_header").toByteArray();

      // send header to client, we already have the first connection's header at this point
      qint64 wroteBytes = sock->write(server_header);

      if(wroteBytes != POST_HEADER_LEN) {
        CLIENT_LOG(sock, "could not send header to client, aborting connection");
        sock->deleteLater();
        return;
      }else{
        CLIENT_LOG(sock, "sent header to client");
      }

      if(sockets.count() > 1) {
        // read connection header back and verify it is the same as the first client
        char header[POST_HEADER_LEN];

        qint64 readBytes = sock->read(header, POST_HEADER_LEN);

        if(readBytes != POST_HEADER_LEN) {
          CLIENT_LOG(sock, "no header received, aborting connection");
          sock->deleteLater();
          return;
        }

        const char *server_header_data = server_header.constData();

        bool word0 = memcmp(header + sizeof(uint32_t) * 0, server_header_data + sizeof(uint32_t) * 0, sizeof(uint32_t));
        bool word1 = memcmp(header + sizeof(uint32_t) * 1, server_header_data + sizeof(uint32_t) * 1, sizeof(uint32_t));

        if(word0 || word1) {
          // header did not match the first connection
          CLIENT_LOG(sock, "header did not match the first connection, aborting");
          sock->deleteLater();
          return;
        }else{
          CLIENT_LOG(sock, "header matches");
        }
      }

      sock->setProperty("state", STATE_SEND_NICKNAME);

      break;
    }
    case STATE_SEND_NICKNAME:
    {
      struct nick_buf_s nick;

      memset(&nick, 0, sizeof(nick));

      nick.cmd[0] = htonl(CMD_NICK);
      nick.cmd[1] = htonl(sizeof(nick.nick));

      strlcpy(nick.nick, "NICK", 5);

      sock->write((const char *)&nick, sizeof(nick));

      sock->setProperty("state", STATE_NONE);

      CLIENT_LOG(sock, "sent nick to host");

      break;
    }
    case STATE_RECV_NICKNAME:
    {
      struct nick_buf_s nick;

      uint32_t cmd_size = sock->property("cmd_size").toUInt();

      if(cmd_size > 0) {
        if(sock->bytesAvailable() < (qint64)sizeof(nick.nick)) {
          // not enough data available yet, keep waiting
          CLIENT_LOGF(sock, "recv nick: not enough data available, only %lli bytes out of %li\n", sock->bytesAvailable(), sizeof(nick));
          return;
        }

        // don't track command info anymore, we have all the data now
        sock->setProperty("cmd", 0);
        sock->setProperty("cmd_size", 0);
      }

      if(cmd[1] != sizeof(nick.nick)) {
        CLIENT_LOGF(sock, "nickname size is wrong (%08X), aborting\n", cmd[1]);
        sock->deleteLater();
        return;
      }

      qint64 readBytes = sock->read(nick.nick, sizeof(nick.nick));

      if(readBytes != sizeof(nick.nick)) {
        CLIENT_LOGF(sock, "could not read nickname from client. got %lli bytes when expecting %li, aborting\n", readBytes, sizeof(nick.nick));
        sock->deleteLater();
        return;
      }

      CLIENT_LOGF(sock, "nick: got %lli bytes\n", readBytes);

      CLIENT_LOGF(sock, "nick is %s\n", nick.nick);

      sock->setProperty("nick", nick.nick);

      sock->setProperty("state", STATE_SEND_INFO);

      // force sending of INFO without waiting for new data
      readyRead();

      break;
    }
    case STATE_SEND_INFO:
    {
      bool info_set = server->property("info_set").toBool();
      info_buf_s server_info = server->property("info").value<info_buf_s>();

      size_t info_payload_size = info_set ? (sizeof(server_info) - sizeof(server_info.cmd)) : 0;

      server_info.cmd[0] = htonl(CMD_INFO);

      // remove the length of the cmd member from the payload size
      server_info.cmd[1] = htonl(info_payload_size);

      server->setProperty("info", QVariant::fromValue(server_info));

      sock->write((const char *)&server_info, sizeof(server_info.cmd) + info_payload_size);

      CLIENT_LOGF(sock, "sent info to host, using core %s\n", server_info.core_name);

      if(info_set) {
        CLIENT_LOG(sock, "next state is send sync");
        sock->setProperty("state", STATE_SEND_SYNC);
        readyRead();
      }else{
        CLIENT_LOG(sock, "next state is none");
        sock->setProperty("state", STATE_NONE);
      }

      break;
    }
    case STATE_RECV_INFO:
    {
      struct info_buf_s info;
      size_t info_payload_size = sizeof(info) - sizeof(info.cmd);
      info_buf_s server_info = server->property("info").value<info_buf_s>();

      info.cmd[0] = htonl(cmd[0]);
      info.cmd[1] = htonl(cmd[1]);

      uint32_t cmd_size = sock->property("cmd_size").toUInt();

      if(cmd_size > 0) {
        if(sock->bytesAvailable() < (qint64)info_payload_size) {
          // not enough data available yet, keep waiting
          CLIENT_LOGF(sock, "recv info: not enough data available, only %lli bytes out of %li\n", sock->bytesAvailable(), info_payload_size);
          return;
        }

        // don't track command info anymore, we have all the data now
        sock->setProperty("cmd", 0);
        sock->setProperty("cmd_size", 0);
      }

      if(cmd[1] != info_payload_size) {
        CLIENT_LOGF(sock, "info size is wrong (%08X), aborting\n", cmd[1]);
        sock->deleteLater();
        return;
      }

      qint64 readBytes = sock->read(info.core_name, info_payload_size);

      if(readBytes != (qint64)info_payload_size) {
        CLIENT_LOGF(sock, "could not read info from client. got %lli bytes when expecting %li, aborting\n", readBytes, info_payload_size);
        sock->deleteLater();
        return;
      }

      CLIENT_LOGF(sock, "info: got %lli bytes\n", readBytes);
      CLIENT_LOGF(sock, "info: core name is %s\n", info.core_name);
      CLIENT_LOGF(sock, "info: core version is %s\n", info.core_version);
      CLIENT_LOGF(sock, "info: content crc is %08X\n", ntohl(info.content_crc));

      if(sockets.indexOf(sock) == 0) {
        if(server->property("first_sync_sent").toBool()) {
          // the first client is just echoing back the info we already have, ignore it
          sock->setProperty("state", STATE_NONE);
          break;
        }else{
          // save the first INFO to echo back to all other clients
          memcpy(&server_info, &info, sizeof(info));
          server->setProperty("info_set", true);
          server->setProperty("info", QVariant::fromValue(server_info));
        }
      }else if(sockets.indexOf(sock) > 0) {
        // make sure other clients have the same INFO
        int info_mismatched = 0;

        info_mismatched |= memcmp(&server_info.core_name, &info.core_name, sizeof(info.core_name));
        // NOTE: ignore core version checking for now
        //info_matches |= memcmp(&server_info.core_version, &info.core_version, sizeof(info.core_version));
        info_mismatched |= memcmp(&server_info.content_crc, &info.content_crc, sizeof(info.content_crc));

        if(!info_mismatched) {
          // info matches
          CLIENT_LOG(sock, "info matches");
          sock->setProperty("state", STATE_NONE);
          break;
        }else{
          // no match, disconnect client
          CLIENT_LOG(sock, "info from client did not match, aborting connection");
          sock->deleteLater();
          return;
        }
      }

      sock->setProperty("state", STATE_SEND_INFO);

      // force sending of INFO without waiting for new data
      readyRead();

      break;
    }
    case STATE_SEND_SYNC:
    {
      union {
        sync_buf_pre5_s sync_pre5;
        sync_buf_s sync;
      };

      size_t sync_payload_size;

      if(server_s.version >= NETPLAY_VERSION_INPUT_UPGRADE)
        sync_payload_size = sizeof(sync);
      else
        sync_payload_size = sizeof(sync_pre5);

      sync_payload_size -= 2 * sizeof(uint32_t);

      memset(&sync, 0, sizeof(sync));

      sync.cmd[0] = htonl(CMD_SYNC);
      sync.cmd[1] = htonl(sync_payload_size);

      for(int i = 0; i < sockets.count() && i < MAX_CLIENTS - 1; ++i) {
        const QPointer<QTcpSocket> &player = sockets.at(i);

        if(!player)
          continue;

        if(player == sock) {
          // we don't count ourselves
          if(server_s.version >= NETPLAY_VERSION_INPUT_UPGRADE)
            sync.client_num = htonl(i+1);
          continue;
        }

        if(!player->property("sync_sent").toBool()) {
          // don't count other players that haven't finished their handshake yet
          continue;
        }

        if(server_s.version >= NETPLAY_VERSION_INPUT_UPGRADE) {
          sync.d_c_mapping[i] = htonl(1U << (i + 1));
        }else{
          sync_pre5.players |= 1U << i;
        }
      }

      uint frameNumber = server->property("frame_count").toUInt();

      QByteArray nick = sock->property("nick").toByteArray();
      const char *nick_data = nick.constData();

      if(server_s.version >= NETPLAY_VERSION_INPUT_UPGRADE) {
        sync.frame_num = htonl(frameNumber);
        /* Device 5 is pad + analog */
        sync.devices[0] = htonl(5);
        sync.devices[1] = htonl(5);

        strlcpy(sync.nick, nick_data, sizeof(sync_pre5.nick));
      }else{
        sync_pre5.players = htonl(sync_pre5.players);
        sync_pre5.frame_num = htonl(frameNumber);
        sync_pre5.devices[0] = htonl(5);
        sync_pre5.devices[1] = htonl(5);

        strlcpy(sync_pre5.nick, nick_data, sizeof(sync_pre5.nick));
      }

      sock->write((const char *)&sync, sync_payload_size + 2*sizeof(uint32_t));

      sock->setProperty("state", STATE_NONE);
      sock->setProperty("sync_sent", true);

      CLIENT_LOG(sock, "sent sync to host");

      if(sockets.indexOf(sock) == 0) {
        server->setProperty("first_sync_sent", true);
      }else{
        // after any non-master connection is up, request a savestate from the master
        reqsave_buf_s req;
        req.cmd[0] = htonl(CMD_REQ_SAVE);
        req.cmd[1] = htonl(0);

        const QPointer<QTcpSocket> &master = sockets.at(0);

        if(master) {
          master->setProperty("savestate_pending", true);
          master->write((const char *)&req, sizeof(req));

          CLIENT_LOG(sock, "requested savestate from the master");
        }
      }

      break;
    }
    case STATE_RECV_PLAY:
    {
      if(cmd[1] > 0) {
        if(sock->bytesAvailable() < cmd[1])
          return;
        // not using the payload right now
        sock->read(cmd[1]);
      }

      const QPointer<QTcpSocket> &master = sockets.at(0);

      if(master) {
        bool savestate_pending = master->property("savestate_pending").toBool();

        if(!savestate_pending) {
          sendMODE(sock);
          CLIENT_LOG(sock, "received PLAY");
        }else{
          // track which player sent the original PLAY command so the 'you' bit in MODE can be set accordingly
          sock->setProperty("sent_play", true);
          CLIENT_LOG(sock, "received PLAY, waiting for savestate transfer to finish before sending MODE");
        }

        sock->setProperty("cmd", 0);
        sock->setProperty("cmd_size", 0);
        sock->setProperty("state", STATE_NONE);
      }

      break;
    }
    case STATE_RECV_LOAD_SAVE:
    {
      loadsave_buf_s loadsave;
      size_t loadsave_payload_size = sizeof(loadsave) - sizeof(loadsave.cmd);
      size_t state_serial_size = cmd[1] - loadsave_payload_size;

      loadsave.cmd[0] = htonl(cmd[0]);
      loadsave.cmd[1] = htonl(cmd[1]);

      CLIENT_LOGF(sock, "receiving savestate data, total size is %u\n", cmd[1]);

      uint32_t cmd_size = sock->property("cmd_size").toUInt();

      if(cmd_size > 0) {
        if(sock->bytesAvailable() < (qint64)cmd_size) {
          // not enough data available yet, keep waiting
          CLIENT_LOGF(sock, "recv loadsave: not enough data available, only %lli bytes out of %u\n", sock->bytesAvailable(), cmd_size);
          return;
        }

        // don't track command info anymore, we have all the data now
        sock->setProperty("cmd", 0);
        sock->setProperty("cmd_size", 0);
      }else{
        if(sock->bytesAvailable() < (qint64)cmd[1]) {
          // Not enough data available yet, but we can't keep waiting.
          // If we could, the cmd_size property would be set accordingly.
          // Hopefully this is never reached
          CLIENT_LOGF(sock, "SHOULD_NOT_SEE_ME recv loadsave: not enough data available, only %lli bytes out of %u, aborting connection\n", sock->bytesAvailable(), cmd[1]);
          sock->deleteLater();
          return;
        }
      }

      qint64 readBytes = sock->read((char*)&loadsave.frame_num, loadsave_payload_size);

      if(readBytes != (qint64)loadsave_payload_size) {
        CLIENT_LOGF(sock, "could not read loadsave from client. got %lli bytes when expecting %li, aborting\n", readBytes, loadsave_payload_size);
        sock->deleteLater();
        return;
      }

      char *state = (char*)malloc(state_serial_size);

      // read arbitrary length savestate serialization data
      readBytes = sock->read((char*)state, state_serial_size);

      if(readBytes != (qint64)state_serial_size) {
        CLIENT_LOGF(sock, "could not read save state serialization from client. got %lli bytes when expecting %li, aborting\n", readBytes, state_serial_size);
        sock->deleteLater();
        return;
      }

      if(sockets.indexOf(sock) != 0) {
        // only the master should be sending us savestates
        CLIENT_LOG(sock, "got savestate from a client that wasn't the master");
        break;
      }

      CLIENT_LOGF(sock, "successfully received savestate of %lu bytes with original size %u\n", state_serial_size, ntohl(loadsave.orig_size));

      const QPointer<QTcpSocket> &master = sockets.at(0);

      if(master) {
        master->setProperty("savestate_pending", false);

        uint frameNumber = ntohl(loadsave.frame_num);

        CLIENT_LOGF(sock, "setting server frame count to savestate value: %u\n", frameNumber);

        for(int i = 0; i < sockets.count(); ++i) {
          const QPointer<QTcpSocket> &player = sockets.at(i);

          if(!player)
            continue;

          if(player != sock) {
            // forward the savestate to everyone else
            player->write((const char *)&loadsave, sizeof(loadsave));
            player->write((const char *)state, state_serial_size);
            CLIENT_LOGF(sock, "sent savestate to player %d\n", sockets.indexOf(player));
          }
        }

        for(int i = 0; i < sockets.count(); ++i) {
          const QPointer<QTcpSocket> &player = sockets.at(i);

          if(!player)
            continue;

          bool sent_play = player->property("sent_play").toBool();

          // find which player sent the original PLAY, so we know who to set the 'you' bit for in the MODE command
          if(sent_play) {
            sendMODE(player);
            player->setProperty("sent_play", false);
          }
        }

        CLIENT_LOGF(sock, "incrementing server frame count to %u (was %u)\n", frameNumber + 1, frameNumber);

        ++frameNumber;

        server->setProperty("frame_count", frameNumber);
        sock->setProperty("state", STATE_NONE);
      }

      break;
    }
    case STATE_RECV_REQ_PORT:
    {
      // ignore any payload
      if(cmd[1] > 0)
        sock->read(cmd[1]);

      // don't track command info anymore, we have all the data now
      sock->setProperty("cmd", 0);
      sock->setProperty("cmd_size", 0);

      sock->setProperty("state", STATE_NONE);

      if(!m_getopt.isSet("multi"))
        break;

      QPointer<QTcpServer> server = new QTcpServer(this);
      connect(server.data(), SIGNAL(acceptError(QAbstractSocket::SocketError)), this, SLOT(acceptError(QAbstractSocket::SocketError)));
      connect(server.data(), SIGNAL(newConnection()), this, SLOT(newConnection()));

      char header[HEADER_LEN] = {0};
      info_buf_s info;

      memset(&info, 0, sizeof(info));

      server->setProperty("state", STATE_HEADER);
      server->setProperty("header", QByteArray(header, HEADER_LEN));
      server->setProperty("info", QVariant::fromValue(info));
      server->setProperty("info_set", false);
      server->setProperty("first_sync_sent", false);
      server->setProperty("master", false);

      qint64 epoch = QDateTime::currentMSecsSinceEpoch() / 1000;
      server->setProperty("created", epoch);
      server->setProperty("updated", epoch);

      Server server_s;
      server_s.server = server;

      m_servers.append(server_s);

      struct newport_buf_s buf;
      buf.cmd[0] = htonl(CMD_NEW_PORT);
      buf.cmd[1] = htonl(sizeof(uint32_t));

      if(!server->listen(QHostAddress::Any, 0)) {
        printf("could not bind to a random port\n");

        buf.port = htonl(0);

        sock->write((const char *)&buf, sizeof(buf));

        return;
      }

      printf("added port %d\n", server->serverPort());

      buf.port = htonl(server->serverPort());

      sock->write((const char *)&buf, sizeof(buf));

      break;
    }
    case STATE_RECV_INPUT:
    {
      input_buf_s input;
      size_t max_input_payload_size = sizeof(input) - sizeof(input.cmd);
      uint32_t cmd_size = cmd[1];

      input.cmd[0] = htonl(cmd[0]);
      input.cmd[1] = htonl(cmd_size);

      if(cmd_size > 0) {
        if(sock->bytesAvailable() < cmd_size) {
          // not enough data available yet, keep waiting
          CLIENT_LOGF(sock, "recv input: not enough data available, only %lli bytes out of %li\n", sock->bytesAvailable(), cmd_size);
          return;
        }

        // don't track command info anymore, we have all the data now
        sock->setProperty("cmd", 0);
        sock->setProperty("cmd_size", 0);
      }

      if(cmd_size > max_input_payload_size) {
        CLIENT_LOGF(sock, "input size too big (%08X), aborting\n", cmd[1]);
        sock->deleteLater();
        return;
      }

      qint64 readBytes = sock->read((char*)&input.frame_num, cmd_size);

      if(readBytes != (qint64)cmd_size) {
        CLIENT_LOGF(sock, "could not read input from client. got %lli bytes when expecting %li, aborting\n", readBytes, cmd_size);
        sock->deleteLater();
        return;
      }

      uint frameNumber = server->property("frame_count").toUInt();

      if(sockets.indexOf(sock) == 0) {
        // this is the first (master) connection
        // server follows the first connection's frame number
        CLIENT_LOGF2(sock, "got INPUT from master, setting server frame count to %u (was %u)", ntohl(input.frame_num), frameNumber);
        dump_uints((const char *)&input, sizeof(input));
        frameNumber = ntohl(input.frame_num);
      }

      // server is transparent, so we send NOINPUT back to all the clients to tell them we aren't sending it any input ourselves
      // (and that the server is done with this frame completely!)
      noinput_buf_s noinput;
      noinput.cmd[0] = htonl(CMD_NOINPUT);
      noinput.cmd[1] = htonl(sizeof(noinput) - sizeof(noinput.cmd));
      noinput.frame_num = htonl(frameNumber);

      // forward this INPUT to everyone else, and send NOINPUT to everyone
      for(int i = 0; i < sockets.count(); ++i) {
        const QPointer<QTcpSocket> &player = sockets.at(i);

        if(!player)
          continue;

        if(player->property("sync_sent").toBool()) {
          if(player != sock) {
            // send this INPUT to all other handshook players
            player->write((const char *)&input, cmd_size + 2*sizeof(uint32_t));
          }

          if(sockets.indexOf(sock) == 0) {
            // send NOINPUT to everyone, but only when getting an INPUT from the master client, as we are keeping our frames in sync with it
            CLIENT_LOGF2(sock, "sending NOINPUT to player %d:", sockets.indexOf(player));
            dump_uints((const char *)&noinput, sizeof(noinput));
            player->write((const char *)&noinput, sizeof(noinput));
          }
        }
      }

      sock->setProperty("state", STATE_NONE);

      if(sockets.indexOf(sock) == 0)
      {
        // Increment server frame number ahead of master client sending a new INPUT with the same frame number.
        // This allows sending MODE to new players as the first event of the next frame, before the master's INPUT.
        CLIENT_LOGF2(sock, "end of frame for master (sent both INPUT and NOINPUT), incrementing server frame count to %u (was %u)\n", frameNumber + 1, frameNumber);
        ++frameNumber;
      }

      qint64 epoch = QDateTime::currentMSecsSinceEpoch() / 1000;

      server->setProperty("frame_count", frameNumber);
      server->setProperty("updated", epoch);

      break;
    }
    default:
      // ignore unknown command
      CLIENT_LOGF(sock, "ignoring unknown command %08X with size %u\n", cmd[0], cmd[1]);

      if(cmd[1] > 0)
        sock->read(cmd[1]);

      break;
  }

  // if we didn't use all the data we got, keep reading
  if(sock->bytesAvailable() > 0)
  {
    //CLIENT_LOGF(sock, "still %lli bytes left, queueing readyRead\n", sock->bytesAvailable());
    readyRead();
  }
}

void MITM::disconnected() {
  QTcpSocket *sock = qobject_cast<QTcpSocket*>(sender());

  if(!sock)
    return;

  Server &server_s = m_servers[sock->property("server").toInt()];
  QPointer<QTcpServer> &server = server_s.server;
  QList<QPointer<QTcpSocket> > &sockets = server_s.sockets;

  if(!server) {
    printf("could not find server for previous connection\n");
    QCoreApplication::quit();
    return;
  }

  qint64 epoch = QDateTime::currentMSecsSinceEpoch() / 1000;
  server->setProperty("updated", epoch);

  sockets.removeOne(sock);

  CLIENT_LOG(sock, "client disconnected");

  sock->deleteLater();
}

void MITM::error(QAbstractSocket::SocketError socketError) {
  // NOTE: only attempt a reconnect here if using a 0-timer
  Q_UNUSED(socketError)

  QTcpSocket *sock = qobject_cast<QTcpSocket*>(sender());

  if(!sock)
    return;

  CLIENT_LOGF(sock, "client got socket error %d\n", socketError);

  // disconnected() will be emitted (because of the error, or by this destructor?)
  sock->deleteLater();
}
