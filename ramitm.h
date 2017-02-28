#ifndef __RAMITM_H
#define __RAMITM_H

#include <QObject>
#include <QtNetwork>
#include <inttypes.h>

#define HEADER_LEN 16
#define NICK_LEN 32

#define CMD_ACK 0x0000
#define CMD_NACK 0x0001
#define CMD_DISCONNECT 0x0002
#define CMD_NICK 0x0020
#define CMD_INFO 0x0022

struct nick_buf_s
{
   uint32_t cmd[2];
   char nick[NICK_LEN];
};

struct info_buf_s
{
   uint32_t cmd[2];
   char core_name[NICK_LEN];
   char core_version[NICK_LEN];
   uint32_t content_crc;
};

enum ClientState {
  STATE_HEADER = 0,
  STATE_SEND_NICKNAME,
  STATE_SEND_INFO,
  STATE_NONE, // NOTE: keep NONE placed after all initial mandatory states
  STATE_RECV_INFO,
  STATE_RECV_NICKNAME
};

class RAMITM : public QObject {
  Q_OBJECT

public:
  RAMITM(QObject *parent = 0);
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

private:
  QTcpServer *m_sock;
  uint m_numClients;
  char m_header[HEADER_LEN];
  info_buf_s m_info;
  bool m_info_set;
};

#endif // __RAMITM_H
