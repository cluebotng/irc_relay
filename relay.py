#!/usr/bin/env python3
"""
MIT License

Copyright (c) 2021 ClueBot NG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import base64
import configparser
import logging
import os
import socket
import ssl
import sys
import threading
from logging.handlers import TimedRotatingFileHandler
from typing import List

logger = logging.getLogger(__name__)


class Config:
    """Configuration data model."""

    def __init__(self, config_path: str):
        self._parser = configparser.ConfigParser()
        if os.path.isfile(config_path):
            self._parser.read(config_path)

    @property
    def irc_host(self):
        return self._parser.get("irc", "host", fallback="irc.libera.chat")

    @property
    def irc_port(self):
        return self._parser.get("irc", "port", fallback=6697)

    @property
    def irc_nick(self):
        return self._parser.get(
            "irc",
            "nick",
            fallback=os.environ.get("CBNG_RELAY_IRC_NICK", "CBNGRelay_Development"),
        )

    @property
    def irc_password(self):
        return self._parser.get(
            "irc", "password", fallback=os.environ.get("CBNG_RELAY_IRC_PASSWORD")
        )

    @property
    def irc_channels(self):
        channels = self._parser.get(
            "irc",
            "channels",
            fallback="#wikipedia-en-cbngfeed,#wikipedia-en-cbngrevertfeed,#wikipedia-en-cbngreview",
        )
        return [c.strip() for c in channels.split(",")]

    @property
    def listener_address(self):
        return self._parser.get("listener", "address", fallback="0.0.0.0")

    @property
    def listener_port(self):
        return self._parser.getint("listener", "port", fallback=3334)


class IrcClient:
    """Basic IRC client designed for relaying."""

    def __init__(
        self,
        host: str,
        port: int,
        nick: str,
        password: str = None,
        channels: List[str] = None,
    ):
        self._host = host
        self._port = port
        self._nick = nick
        self._password = password
        self._channels = channels if channels else []
        self._c = None
        self._joined_channels = set()
        self._in_authentication = False
        self._running = False

    def _connect(self):
        context = ssl.create_default_context()
        self._c = context.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=self._host,
        )
        self._c.connect((self._host, self._port))
        self._running = True

    def stop(self):
        self._running = False
        self._c.close()
        self._c = None
        self._joined_channels = set()

    def _send(self, message):
        logger.info("Sending to server: %s", message)
        self._c.send("{}\r\n".format(message).encode("utf-8"))

    def send_to_channel(self, channel, message):
        clean_message = message.replace("\r", "").replace("\n", "")
        if channel not in self._joined_channels:
            logger.warning(
                "Skipping non-joined channel (%s) message: %s", channel, clean_message
            )
            return

        self._send("PRIVMSG {} :{}".format(channel, clean_message))

    def loop(self):
        self._connect()

        while self._running:
            lines = self._c.recv(512).decode("utf-8").splitlines()
            if not lines:
                logger.info("Received from server: %s", lines)
                raise RuntimeError("Disconnected")

            for line in lines:
                line, line_parts = line.strip(), line.strip().split(" ")
                logger.info("Processing from server: %s", line)

                # Reply to PING
                if line.startswith("PING "):
                    self._send("PONG {}".format(line.split(":")[1]))
                    continue

                # Send user details after initial banner
                if line.endswith("*** No Ident response"):
                    if self._password:
                        self._send("CAP REQ :sasl")
                    self._send("NICK {}".format(self._nick))
                    self._send("USER {} * * :{}".format(self._nick, self._nick))
                    continue

                # Request plain login
                if line.endswith("CAP * ACK :sasl"):
                    self._in_authentication = True
                    self._send("AUTHENTICATE PLAIN")
                    continue

                # Provide authentication details
                if line.endswith("AUTHENTICATE +"):
                    if not self._in_authentication:
                        raise RuntimeError(
                            "Got authentication request outside of authentication handshake"
                        )
                    logger.info("Sending SASL authentication")
                    auth_string = base64.b64encode(
                        "{}\0{}\0{}".format(
                            self._nick,
                            self._nick,
                            self._password,
                        ).encode("utf-8")
                    ).decode("utf-8")

                    self._send("AUTHENTICATE {}".format(auth_string))
                    continue

                # End the capability negotiation
                if line.endswith("SASL authentication successful"):
                    self._in_authentication = False
                    self._send("CAP END")

                # Join channels
                if line.endswith("End of /MOTD command."):
                    for channel in self._channels:
                        self._send("JOIN {}".format(channel))
                        continue

                # Store when we actually joined
                if (
                    len(line_parts) >= 3
                    and line_parts[1] == "353"
                    and line_parts[2] == self._nick
                    and line_parts[4] in self._channels
                ):
                    logger.info("Recording joined channel: %s", line_parts[4])
                    self._joined_channels.add(line_parts[4])
                    continue


class UdpListener:
    """Basic UDP server designed to decode messages from the Bot."""

    def __init__(self, irc_client: IrcClient, address: str, port: int):
        self._irc_client = irc_client
        self._address = address
        self._port = port
        self._s = None
        self._running = False

    def _connect(self):
        self._s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._s.bind((self._address, self._port))
        self._running = True

    def stop(self):
        self._running = False

    def loop(self):
        self._connect()

        while self._running:
            data, _ = self._s.recvfrom(1500)
            if not data:
                continue

            data = data.decode("utf-8").strip()
            if ":" not in data:
                logger.error("Malformed data: %s", data)
                continue

            parts = data.split(":")
            channel, message = parts[0], ":".join(parts[1:]).strip()
            self._irc_client.send_to_channel(channel, message)


def main():
    """Main logic - run the IRC server on a thread and the listener on the parent."""
    log_format = "%(asctime)s [%(levelname)s] %(message)s"
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format=log_format)

    home_dir = os.environ.get("TOOL_DATA_DIR", os.environ.get("HOME"))
    log_dir = os.path.join(home_dir, "logs")
    log_file = os.path.join(log_dir, "irc_relay.log")

    os.makedirs(log_dir, exist_ok=True)
    log_file = TimedRotatingFileHandler(log_file, when="D", interval=1, backupCount=10)
    log_file.setFormatter(logging.Formatter(log_format))
    logger.addHandler(log_file)

    cfg = Config("relay.cfg")

    irc = IrcClient(
        cfg.irc_host, cfg.irc_port, cfg.irc_nick, cfg.irc_password, cfg.irc_channels
    )
    listener = UdpListener(irc, cfg.listener_address, cfg.listener_port)

    irc_server = threading.Thread(target=irc.loop)
    udp_server = threading.Thread(target=listener.loop)

    irc_server.start()
    udp_server.start()

    while irc_server.is_alive() and udp_server.is_alive():
        pass

    logger.error("Thread died: %s / %s", irc_server.is_alive(), udp_server.is_alive())
    udp_server.join()
    irc_server.join()


if __name__ == "__main__":
    main()
