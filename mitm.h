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

#ifndef __MITM_H
#define __MITM_H

#include <QObject>
#include <QtNetwork>
#include <QCommandLineParser>
#include <inttypes.h>

#define NETPLAY_MAGIC 0x52414E50
#define NETPLAY_VERSION_FIRST 4
#define NETPLAY_VERSION_INPUT_UPGRADE 5
#define NETPLAY_VERSION_LAST NETPLAY_VERSION_INPUT_UPGRADE

#define HEADER_LEN 16
#define POST_HEADER_LEN 8
#define NICK_LEN 32
#define MAX_CLIENTS 32

#define CMD_ACK 0x0000
#define CMD_NACK 0x0001
#define CMD_DISCONNECT 0x0002
#define CMD_INPUT 0x0003
#define CMD_NOINPUT 0x0004
#define CMD_NICK 0x0020
#define CMD_INFO 0x0022
#define CMD_SYNC 0x0023
#define CMD_PLAY 0x0025
#define CMD_MODE 0x0026
#define CMD_REQ_SAVE 0x0041
#define CMD_LOAD_SAVE 0x0042

// custom commands not part of RetroArch
#define CMD_REQ_PORT 0x4649
#define CMD_NEW_PORT 0x464a

struct nick_buf_s {
  uint32_t cmd[2];
  char nick[NICK_LEN];
};

struct info_buf_s {
  uint32_t cmd[2];
  char core_name[NICK_LEN];
  char core_version[NICK_LEN];
  uint32_t content_crc;
};

struct sync_buf_pre5_s {
  uint32_t cmd[2];
  uint32_t frame_num;
  uint32_t players; // high bit == paused?
  uint32_t flip_frame;
  uint32_t devices[16];
  char nick[32];
};

struct sync_buf_s {
  uint32_t cmd[2];
  uint32_t frame_num;
  uint32_t client_num; // high bit == paused?
  uint32_t devices[16];
  uint8_t share_modes[16];
  uint32_t d_c_mapping[16];
  char nick[32];
};

struct mode_buf_pre5_s {
  uint32_t cmd[2];
  uint32_t frame_num;
  uint16_t target;
  uint16_t player_num;
};

struct mode_buf_s {
  uint32_t cmd[2];
  uint32_t frame_num;
  uint16_t target;
  uint16_t client_num;
  uint32_t devices;
  uint8_t share_modes[16];
  char nick[32];
};

struct input_buf_s {
  uint32_t cmd[2];
  uint32_t frame_num;
  uint32_t player; // high bit == is server data
  uint32_t data[32]; // actual size will be less
};

struct noinput_buf_s {
  uint32_t cmd[2];
  uint32_t frame_num;
};

struct reqsave_buf_s {
  uint32_t cmd[2];
};

struct loadsave_buf_s {
  uint32_t cmd[2];
  uint32_t frame_num;
  uint32_t orig_size;
};

struct newport_buf_s {
  uint32_t cmd[2];
  uint32_t port;
};

struct Server {
  bool operator==(const Server &other) {
    return server == other.server;
  }

  uint32_t version;
  QPointer<QTcpServer> server;
  QList<QPointer<QTcpSocket> > sockets;
};

enum ClientState {
  STATE_HEADER = 0,
  STATE_POST_HEADER, // Due to header format changing, we read as two parts
  STATE_SEND_NICKNAME,
  STATE_SEND_INFO,
  STATE_SEND_SYNC,
  STATE_NONE, // NOTE: keep NONE placed after all initial mandatory states
  STATE_RECV_INFO,
  STATE_RECV_NICKNAME,
  STATE_RECV_PLAY,
  STATE_RECV_INPUT,
  STATE_RECV_REQ_SAVE,
  STATE_RECV_LOAD_SAVE,
  STATE_RECV_REQ_PORT
};

class MITM : public QObject {
  Q_OBJECT

public:
  MITM(QObject *parent = 0);
  static void handleSIGINT(int);
  static void handleSIGTERM(int);

public slots:
  void start();

private slots:
  void acceptError(QAbstractSocket::SocketError socketError);
  void newConnection();
  void readyRead();
  void disconnected();
  void error(QAbstractSocket::SocketError socketError);
  void timeout();
  quint16 findFreePort();

private:
  void sendMODE(QTcpSocket *sock);

  QPointer<QTcpServer> m_server;
  QList<Server> m_servers;
  QCommandLineParser m_getopt;
  QPair<quint16, quint16> m_portRange;
  QTimer m_timer;
};

Q_DECLARE_METATYPE(info_buf_s)

#endif // __MITM_H
