#include "ramitm.h"
#include <stdio.h>

#ifdef Q_OS_UNIX
#include <signal.h>
#endif

#include <arpa/inet.h>

#define QC_STR(x) x.toStdString().c_str()

size_t strlcpy(char *dest, const char *source, size_t size)
{
  size_t src_size = 0;
  size_t        n = size;

  if(n)
    while(--n && (*dest++ = *source++)) src_size++;

  if(!n) {
    if(size) *dest = '\0';
    while(*source++) src_size++;
  }

  return src_size;
}

RAMITM::RAMITM(QObject *parent) :
  QObject(parent)
  ,m_sock(new QTcpServer(this))
  ,m_numClients(0)
  ,m_header()
  ,m_info()
{
  memset(&m_info, 0, sizeof(m_info));

#ifdef Q_OS_UNIX
  struct sigaction sigint, sigterm;

  sigint.sa_handler = RAMITM::handleSIGINT;
  sigemptyset(&sigint.sa_mask);
  sigint.sa_flags = 0;
  sigint.sa_flags |= SA_RESTART;

  sigaction(SIGINT, &sigint, 0);

  sigterm.sa_handler = RAMITM::handleSIGTERM;
  sigemptyset(&sigterm.sa_mask);
  sigterm.sa_flags = 0;
  sigterm.sa_flags |= SA_RESTART;

  sigaction(SIGTERM, &sigterm, 0);
#endif

  connect(m_sock, SIGNAL(acceptError(QAbstractSocket::SocketError)), this, SLOT(acceptError(QAbstractSocket::SocketError)));
  connect(m_sock, SIGNAL(newConnection()), this, SLOT(newConnection()));
}

void RAMITM::start() {
  if(!m_sock->listen(QHostAddress::Any, 5905)) {
    printf("could not bind to port\n");
    QCoreApplication::quit();
    return;
  }

  printf("bound to port\n");
}

void RAMITM::handleSIGINT(int) {
  printf("quitting...\n");
  QCoreApplication::quit();
}

void RAMITM::handleSIGTERM(int) {
  printf("quitting...\n");
  QCoreApplication::quit();
}

void RAMITM::acceptError(QAbstractSocket::SocketError socketError) {
  printf("got accept() error code %d\n", socketError);
}

void RAMITM::newConnection() {
  QTcpSocket *sock = m_sock->nextPendingConnection();

  if(!sock)
    return;

  printf("got new connection from %s\n", QC_STR(sock->peerAddress().toString()));

  connect(sock, SIGNAL(readyRead()), this, SLOT(readyRead()));
  connect(sock, SIGNAL(disconnected()), this, SLOT(disconnected()));
  connect(sock, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(error(QAbstractSocket::SocketError)));
}

void RAMITM::readyRead() {
  QTcpSocket *sock = static_cast<QTcpSocket*>(sender());

  if(!sock)
    return;

  ClientState state = static_cast<ClientState>(sock->property("state").toUInt());
  uint32_t cmd[2] = {0};

  printf("readyRead: %lli bytes available, state is %d for host %s\n", sock->bytesAvailable(), state, QC_STR(sock->peerAddress().toString()));

  /*int bytes = sock->bytesAvailable();

  for(int i = 0; i < bytes; i++) {
    char a;
    sock->read(&a, 1);
    printf(" %08X", a);
  }

  printf("\n");*/

  // check for end of mandatory state handling before accepting any new commands
  if(state >= STATE_NONE) {
    if(sock->bytesAvailable() < 8) {
      // wait for more data
      printf("not enough data for a command yet, keep waiting\n");
      return;
    }

    // after the header we switch to a command-based format
    uint32_t newcmd[2];

    qint64 readBytes = sock->read((char*)newcmd, 8);

    if(readBytes != 8) {
      printf("invalid data received from %s, aborting connection\n", QC_STR(sock->peerAddress().toString()));
      sock->deleteLater();
      return;
    }

    cmd[0] = ntohl(newcmd[0]);
    cmd[1] = ntohl(newcmd[1]);

    if(sock->bytesAvailable() < (qint64)cmd[1]) {
      printf("WARNING: not enough data, we have %lli bytes available but the command payload size is %u\n", sock->bytesAvailable(), cmd[1]);
    }

    if(state == STATE_NONE) {
      if(cmd[0] == CMD_ACK) {
        printf("ACK\n");

        // acknowledge, wait for next command
        if(sock->bytesAvailable() > 0)
        {
          readyRead();
          return;
        }
      }

      if(cmd[0] == CMD_NACK || cmd[0] == CMD_DISCONNECT) {
        printf("client %s didn't like our data or requested a disconnect, aborting connection\n", QC_STR(sock->peerAddress().toString()));
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
        default:
          break;
      }

      printf("got command %08X with payload size %u\n", cmd[0], cmd[1]);
    }
  }

  switch(state) {
    case STATE_HEADER:
    {
      if(m_numClients == 0) {
        if(sock->bytesAvailable() < 16) {
          // not enough data available yet, keep waiting
          printf("header: not enough data available, only %lli bytes out of 16\n", sock->bytesAvailable());
          return;
        }else{
          char header[HEADER_LEN];

          qint64 readBytes = sock->read(header, HEADER_LEN);

          if(readBytes != HEADER_LEN) {
            printf("no header received from %s, aborting connection\n", QC_STR(sock->peerAddress().toString()));
            sock->deleteLater();
            return;
          }

          printf("header: got %lli bytes from %s\n", readBytes, QC_STR(sock->peerAddress().toString()));

          // store the first client's header to use for all others
          memcpy(m_header, header, HEADER_LEN);
        }
      }

      // send header to client, we already have the first connection's header at this point
      qint64 wroteBytes = sock->write(m_header, HEADER_LEN);

      if(wroteBytes != HEADER_LEN) {
        printf("could not send header to client %s, aborting connection\n", QC_STR(sock->peerAddress().toString()));
        sock->deleteLater();
        return;
      }else{
        printf("sent header to client %s\n", QC_STR(sock->peerAddress().toString()));
      }

      if(m_numClients > 0) {
        // read connection header back and verify it is the same as the first client
        char header[HEADER_LEN];

        qint64 readBytes = sock->read(header, HEADER_LEN);

        if(readBytes != HEADER_LEN) {
          printf("no header received from %s, aborting connection\n", QC_STR(sock->peerAddress().toString()));
          sock->deleteLater();
          return;
        }

        printf("SVR header: %08X %08X %08X %08X\n", m_header[0], m_header[1], m_header[2], m_header[3]);
        printf("CLT header: %08X %08X %08X %08X\n", header[0], header[1], header[2], header[3]);

        if(memcmp(header, m_header, HEADER_LEN)) {
          // header did not match the first connection
          printf("header did not match the first connection, aborting\n");
          sock->deleteLater();
          return;
        }else{
          printf("header matches\n");
        }
      }

      ++m_numClients;

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

      printf("sent nick to host\n");

      break;
    }
    case STATE_RECV_NICKNAME:
    {
      struct nick_buf_s nick;

      if(sock->bytesAvailable() < (qint64)sizeof(nick.nick)) {
        // not enough data available yet, keep waiting
        printf("recv nick: not enough data available, only %lli bytes out of %li\n", sock->bytesAvailable(), sizeof(nick));
        return;
      }

      if(cmd[1] != sizeof(nick.nick)) {
        printf("nickname size is wrong (%08X), aborting\n", cmd[1]);
        sock->deleteLater();
        return;
      }

      qint64 readBytes = sock->read(nick.nick, sizeof(nick.nick));

      if(readBytes != sizeof(nick.nick)) {
        printf("could not read nickname from client. got %lli bytes when expecting %li, aborting\n", readBytes, sizeof(nick.nick));
        sock->deleteLater();
        return;
      }

      printf("nick: got %lli bytes from %s\n", readBytes, QC_STR(sock->peerAddress().toString()));

      printf("nick is %s\n", nick.nick);

      sock->setProperty("state", STATE_SEND_INFO);

      // force sending of INFO without waiting for new data
      readyRead();

      break;
    }
    case STATE_SEND_INFO:
    {
      size_t info_payload_size = sizeof(m_info) - sizeof(m_info.cmd);

      memset(&m_info, 0, sizeof(m_info));

      m_info.cmd[0] = htonl(CMD_INFO);

      // remove the length of the cmd member from the payload size
      m_info.cmd[1] = htonl(info_payload_size);

      sock->write((const char *)&m_info, sizeof(m_info));

      sock->setProperty("state", STATE_NONE);

      printf("sent info to host\n");

      break;
    }
    case STATE_RECV_INFO:
    {
      struct info_buf_s info;
      size_t info_payload_size = sizeof(info) - sizeof(info.cmd);

      if(sock->bytesAvailable() < (qint64)info_payload_size) {
        // not enough data available yet, keep waiting
        printf("recv info: not enough data available, only %lli bytes out of %li\n", sock->bytesAvailable(), info_payload_size);
        return;
      }

      if(cmd[1] != info_payload_size) {
        printf("info size is wrong (%08X), aborting\n", cmd[1]);
        sock->deleteLater();
        return;
      }

      qint64 readBytes = sock->read(info.core_name, info_payload_size);

      if(readBytes != (qint64)info_payload_size) {
        printf("could not read info from client. got %lli bytes when expecting %li, aborting\n", readBytes, info_payload_size);
        sock->deleteLater();
        return;
      }

      if(m_numClients == 1) {
        // save the first INFO to echo back to all other clients
        memcpy(&m_info, &info, sizeof(info));
      }

      printf("info: got %lli bytes from %s\n", readBytes, QC_STR(sock->peerAddress().toString()));

      printf("info: core name is %s\n", info.core_name);
      printf("info: core version is %s\n", info.core_version);
      printf("info: content crc is %08X\n", info.content_crc);

      sock->setProperty("state", STATE_SEND_INFO);

      // force sending of INFO without waiting for new data
      readyRead();

      break;
    }
    default:
      // ignore unknown command
      printf("ignoring unknown command %08X with size %u\n", cmd[0], cmd[1]);

      if(cmd[1] > 0)
        sock->read(cmd[1]);

      break;
  }

  // if we didn't use all the data we got, keep reading
  if(sock->bytesAvailable() > 0)
  {
    readyRead();
    return;
  }
}

void RAMITM::disconnected() {
  QTcpSocket *sock = static_cast<QTcpSocket*>(sender());

  if(!sock)
    return;

  printf("client %s disconnected\n", QC_STR(sock->peerAddress().toString()));

  sock->deleteLater();

  --m_numClients;
}

void RAMITM::error(QAbstractSocket::SocketError socketError) {
  // NOTE: only attempt a reconnect here if using a 0-timer

  QTcpSocket *sock = static_cast<QTcpSocket*>(sender());

  if(!sock)
    return;

  printf("client %s got socket error %d\n", QC_STR(sock->peerAddress().toString()), socketError);

  // disconnected() will be emitted (because of the error, or by this destructor?)
  sock->deleteLater();
}
