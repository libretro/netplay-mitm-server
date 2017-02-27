#include <QCoreApplication>
#include "ramitm.h"

int main(int argc, char *argv[]) {
  QCoreApplication app(argc, argv);

  RAMITM ramitm;
  ramitm.start();

  return app.exec();
}
