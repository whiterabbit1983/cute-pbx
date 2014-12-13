import re
import sys
import sqlite3
from twisted.python import log
from twisted.protocols import sip
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory


def parse_uri(uri):
    '''
    Parse SIP URI in the format
    <sip:username@hostname>.
    Returns a tuple (username, hostname)
    '''
    r = re.match(".*<sip:([\w\d]+)@([\w\d\.]+)>", uri)
    return r.groups(0)


class DataBase(object):
    def __init__(self, name):
        self.conn = sqlite3.connect(name)
        self.cur = self.conn.cursor()
        self._prepare()

    def _prepare(self):
        sql = '''
        create table if not exists Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            host TEXT NOT NULL
        )
        '''

        self.cur.execute(sql)

    def getuserhost(self, name):
        sql = '''
        select host from Users
        where username = ?
        '''

        self.cur.execute(sql, (name,))
        res = self.cur.fetchone()
        if not res:
            return None

        if not isinstance(res[0], unicode):
            return res[0]
        return res[0].encode("utf-8")

    def updateuser(self, username, host):
        sql = '''
        replace into Users (username, host)
        values (?, ?)
        '''

        self.cur.execute(sql, (username, host))    


class SipProxy(sip.Proxy):
    PORT = 5060

    def __init__(self):
        self.db = DataBase("users.db")
        sip.Proxy.__init__(self, host="127.0.0.1", port=5060)

    def check_user(self, message, field="to"):
        user, _ = parse_uri(message.headers[field][0])
        return bool(self.db.getuserhost(user))

    def return_OK(self, message, addr):
        resp = self.responseFromRequest(200, message)
        log.msg("sending 200 OK to {}".format(addr))
        self.transport.write(resp.toString(), addr)

    def return_FORBIDDEN(self, message, addr):
        resp = self.responseFromRequest(403, message)
        log.msg("sending 403 Forbidden to {}".format(addr))
        self.transport.write(resp.toString(), addr)

    def return_TRYING(self, message, addr):
        resp = self.responseFromRequest(100, message)
        log.msg("sending 100 Trying to {}".format(addr))
        self.transport.write(resp.toString(), addr)

    def return_RINGING(self, message, addr):
        resp = self.responseFromRequest(180, message)
        log.msg("sending 180 Ringing to {}".format(addr))
        self.transport.write(resp.toString(), addr)

    def return_NOTFOUND(self, message, addr):
        resp = self.responseFromRequest(404, message)
        self.transport.write(resp.toString(), addr)        

    def redirect(self, message, addr):
        log.msg(addr)
        self.transport.write(message.toString(), addr)

    def handle_request(self, message, addr):
        if hasattr(message, "code"):
            if message.code == 180:
                handling_method = "handle_RINGING"
            elif message.code == 200:
                handling_method = "handle_OK"
            else:
                handling_method = "handle_OK"
        else:
            handling_method = "handle_{}".format(message.method)
        if hasattr(self, handling_method):
            getattr(self, handling_method)(message, addr)
        else:
            return self.return_OK(message, addr)

    def handle_RINGING(self, message, addr):
        frm, to = message.headers["from"][0], message.headers["to"][0]
        _, peer_host = parse_uri(to)
        if not self.check_user(message, field="from"):
            log.msg("malicious RINGING from {} to {}".format(frm, to))
        if not self.check_user(message):
            log.msg("destination {} not found".format(to))
            self.return_NOTFOUND(message, addr)
        self.return_RINGING(message, (peer_host, self.PORT))

    def handle_OK(self, message, addr):
        frm, to = message.headers["from"][0], message.headers["to"][0]
        _, peer_host = parse_uri(to)
        self.return_OK(message, (peer_host, self.PORT))

    def handle_INVITE(self, message, addr):
        log.msg(message.toString())
        frm, to = message.headers["from"][0], message.headers["to"][0]
        peer_user, _ = parse_uri(to)
        peer_host = self.db.getuserhost(peer_user)
        log.msg(
            "INVITE from {} to {}".format(frm, to))
        if self.check_user(message, field="from"):
            log.msg("sending TRYING to {}".format(frm))
            self.return_TRYING(message, addr)
            # check if caller exists
            if not self.check_user(message):
                # check if callee exists
                log.msg("{} not found".format(to))
                return self.return_NOTFOUND(message, addr)
            # sending INVITE further to the destination
            log.msg("resending INVITE to {}".format(to))
            self.redirect(message, (peer_host, self.PORT))

    def handle_REGISTER(self, message, addr):
        log.msg(message.toString())
        log.msg("REGISTER from {}".format(message.headers["to"]))
        user, host = parse_uri(message.headers["to"][0])
        if self.check_user(message):
            self.db.updateuser(user, host)
            log.msg("{} registered OK".format(user))
            return self.return_OK(message, addr)
        return self.return_FORBIDDEN(message, addr)


if __name__ == "__main__":
    log.startLogging(sys.stdout)
    reactor.listenUDP(5060, SipProxy(), "127.0.0.1")
    reactor.run()
