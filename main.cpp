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

#include <QCoreApplication>
#include "ramitm.h"

int main(int argc, char *argv[]) {
  QCoreApplication app(argc, argv);

  RAMITM ramitm;
  ramitm.start();

  return app.exec();
}
