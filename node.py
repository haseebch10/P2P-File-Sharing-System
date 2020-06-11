
import json
from Address import Address
import copy
import random
from time import sleep
import sys
import threading
import hashlib
import socket
import time

from threading import Thread

M=8
filesList = []




class Message(object):
    @staticmethod
    def getjson(subject, payload=""):
        if isinstance(payload, dict) and subject == "my_finger_table":
            payload = copy.deepcopy(payload)
            for k, v in payload.items():
                payload[k] = str(v)
            payload = json.dumps(payload)
        msg = {
            "subject": subject,
            "payload": payload
        }
        return json.dumps(msg)

    @staticmethod
    def parse_message(msg):
        try:
            ret = json.loads(msg)
        except Exception:
            print("Return message not a valid JSON")
            print(msg)
            return None
        else:
            return ret


class MessageHandlerThread(Thread):
    def __init__(self, node_instance, from_socket):
        Thread.__init__(self)
        self.node = node_instance
        self.from_socket = from_socket
        self.daemon = True

    def run(self):
        response = readsock(self.from_socket)
        self.handle_message(response)

    def __del__(self):
        self.from_socket.close()

    def handle_message(self, msg):
        msg_dict = Message.parse_message(msg)
        subject = msg_dict["subject"]
        payload = msg_dict["payload"]
        result = ""

        if subject == "find_succ_for_id":
            successor = self.node.findsucc(payload)
            result = Message.getjson("set_your_succ", str(successor))

        elif subject == "get_your_succ":
            result = Message.getjson("my_succ", str(self.node.get_successor()))

        elif subject == "get_your_pre":
            result = Message.getjson("my_pre", str(self.node.predecessor))

        elif subject == "find_closest_p":
            result = Message.getjson("closest_p", str(self.node.closestprecedfinger(payload)))

        elif subject == "i_am_your_pre":
            addr = Address.get_address_from_string(payload)
            self.node.notified(addr)
            return

        elif subject == "get_your_finger_table":
            result = Message.getjson("my_finger_table", self.node.finger_table)

        elif subject == "log":
            print(str(payload))
            return

        elif subject == "areyoualive":
            result = Message.getjson("iamalive")

        else:
            result = Message.getjson("log", "Invalid command!")

        sendsock(self.from_socket, result)

class Address(object):
    def __init__(self, ip, port):
        super().__init__()
        self.ipv4 = ip
        self.port = int(port)

    @staticmethod
    def get_address_from_string(str):
        if len(str) > 10:
            split = str.split(":")
            ip = split[0]
            port = split[1]
            return Address(ip, port)
        else:
            return None

    def to_string(self):
        return str(self)

    def __eq__(self, other):
        if self is None or other is None:
            return False

        if isinstance(other, Address) == False:
            if len(other) > 10:
                other = Address.get_address_from_string(other)
            else:
                return False
        return self.ipv4 == other.ipv4 and self.port == other.port

    def __str__(self):
        return "{0}:{1}".format(self.ipv4, self.port)

class FixFingers(Thread):

    def __init__(self, node):
        Thread.__init__(self)
        self.node = node
        self.daemon = False
        self.checking = True

    def run(self):
        sleep_time = 0
        while self.checking:
            index = random.randint(2,M)
            ith_finger_start_index = (self.node.id + 2**(index-1)) % (2**M)
            ith_finger = self.node.findsucc(ith_finger_start_index)
            self.node.update_ith_finger(index, ith_finger)
            sleep_time = sleep_time + 0.5 if sleep_time < 6 else random.randint(2,6)
            sleep(sleep_time)

    def die(self):
        self.checking = False

class Listener(Thread):
        def __init__(self, node_instance):
            Thread.__init__(self)
            self.daemon = False
            self.node = node_instance
            self.address = node_instance.local_address
            self.sock = socket.socket()
            self.listening = False
            sleeptime = 5

            while not self.listening:
                try:
                    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.sock.bind((self.address.ipv4, self.address.port))
                    self.sock.listen(5)
                    self.listening = True
                except Exception as e:
                    print("Could not start the server on {0}:{1}".format(self.address.ipv4, self.address.port))
                    print(str(e))
                    print("Trying to rebind...")
                    time.sleep(sleeptime)
                    self.sock.close()
                    sleeptime += 1

        def __del__(self):
            try:
                self.sock.close()
            except Exception:
                pass

        def run(self):
            while self.listening:
                try:
                    conn, addr = self.sock.accept()
                except Exception as e:
                    print("Cannot accept connection...")
                    print(str(e))
                else:
                    MessageHandlerThread(self.node, conn).start()

        def die(self):
            self.listening = False

class Stabilize(threading.Thread):
    def __init__(self, node):
        threading.Thread.__init__(self)
        self.daemon = False
        self.node = node
        self.alive = True

    def run(self):
        while self.alive:
            succ = self.node.get_successor()
            if succ is not None and isinstance(succ, Address) == False:
               succ = Address.get_address_from_string(succ)
            if succ is None or succ == self.node.local_address:
                self.node.fillsuc()

            succ = self.node.get_successor()
            if succ is not None and succ != self.node.local_address:
                succ_pre_q = queryadd(succ, Message.getjson("get_your_pre"))
                if succ_pre_q is None:
                    self.node.delete_successor()
                else:
                    succ_pre = Address.get_address_from_string(succ_pre_q["payload"])
                    if succ_pre is not None:
                        if succ_pre == succ:
                            self.node.notify(succ)
                        else:
                            succ_offset = find_offset(self.node.id, hashadd(succ))
                            succ_pre_offset = find_offset(self.node.id, hashadd(succ_pre))
                            if succ_pre_offset > 0 and succ_pre_offset < succ_offset:
                                self.node.update_ith_finger(1, succ_pre)

            time.sleep(1)

    def die(self):
        self.alive = False

def hashadd(addr):

    if addr is None:
        return None
    if isinstance(addr, Address) == False and len(addr) > 0:
        addr = Address.get_address_from_string(addr)

    s = "{0}:{1}".format(addr.port, addr.ipv4)
    hash = hashlib.sha1()
    hash.update(s.encode())
    hash_value = int(hash.hexdigest(), 16)
    return hash_value % (2 ** M)

def readsock(socket):
    output = ""
    while True:
        data = socket.recv(512)
        data = bytes.decode(data)
        if data[-2:] == "\r\n":
            output += data[:-2]
            break
        output += data
    return output

def sendsock(sock, msg):
    serialized_msg = (str(msg) + "\r\n").encode()
    try:
        sock.sendall(serialized_msg)
    except Exception as e:
        return None

def addresssend(address, msg):
    addr = (address.ipv4, address.port)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(addr)
    except Exception:
        return None
    sendsock(sock, msg)

def socketquery(sock, msg):
    sendsock(sock, msg)
    time.sleep(1)
    result = readsock(sock)
    res = Message.parse_message(result)
    if res is not None and res["subject"] != "log":
        return res
    return None

def queryadd(address, msg):
    if address is None or msg is None or len(msg) == 0:
        return

    if isinstance(address, Address) == False and len(address) > 0:
        address = Address.get_address_from_string(address)

    addr = (address.ipv4, address.port)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(addr)
    except Exception:
        return None
    return socketquery(sock, msg)

def find_offset(initial, final):
    ret = final - initial
    if ret < 0:
        ret = 2**M + ret
    return ret

def print_error(e):
    print("\n\t\t---")
    print(str(e))
    print("\t\t---\n")

class CheckPredecessor(Thread):

    def __init__(self, node):
        Thread.__init__(self)
        self.daemon = False
        self.node = node
        self.working = True

    def run(self):
        while self.working:
            pre = self.node.predecessor
            if pre is not None:
                alive_query = queryadd(pre, Message.getjson("areyoualive"))
                if alive_query is None or alive_query["subject"] != "iamalive":
                    if self.node.get_successor() == self.node.local_address:
                        self.node.set_predecessor(self.node.local_address)
                    else:
                        self.node.set_predecessor(self.node.findpredec(self.node.id))
            else:
                self.node.set_predecessor(self.node.local_address)
            time.sleep(6)


    def die(self):
        self.working = False





class Node(Thread):
    def __init__(self, ip_addr, port, connect_to=None, seed=False):
        Thread.__init__(self)
        self.local_address = Address(ip_addr, port)
        self.seed = seed
        self.id = hashadd(self.local_address)
        print("\nNode initialized with id {0} at address {1}\n".format(self.id, self.local_address.to_string()))
        self.set_predecessor(self.local_address)
        self.init_finger_table()
        self.listener = Listener(self)
        self.stabilizer = Stabilize(self)
        self.finger_fixer = FixFingers(self)
        self.predecessor_stabilizer = CheckPredecessor(self)
        self.contact_addr = connect_to
        self.file= filesList

    def __del__(self):
        if self.listener is not None:
            self.listener.die()
        if self.stabilizer is not None:
            self.stabilizer.die()
        if self.finger_fixer is not None:
            self.finger_fixer.die()
        if self.predecessor_stabilizer is not None:
            self.predecessor_stabilizer.die()

    def get_id_dict(self):
        return {"id": self.id, "local_address": str(self.local_address)}

    def ask_for_ip_port(self):
        if self.seed == False:
            while True:
                print("\nEnter the address of the node you wish to join. For example, 'localhost:8433' or '172.32.21.1:64356'.")
                print("Hit Return if you are the seed node.")
                join_addr = input()
                if len(join_addr) == 0:
                    break
                elif len(join_addr) > 10:
                    self.join_(Address.get_address_from_string(join_addr))
                    return
                else:
                    print("\nInvalid address. Please try again.\n")

        print("\nSeed node initialized with address {0} and id {1}. Waiting for other nodes to join the chord network.\n".format(self.local_address.to_string(), self.id))

    def run(self):
        self.listener.start()
        if self.contact_addr is None:
            self.ask_for_ip_port()
        else:
            self.join_(self.contact_addr)

        self.stabilizer.start()
        self.finger_fixer.start()
        self.predecessor_stabilizer.start()

    def init_finger_table(self):
        self.finger_table = dict()
        for i in range(1, M+1):
            self.finger_table[i] =  None
        self.update_ith_finger(1, self.local_address)

    def join_(self, receiving_node_addr):

        response = queryadd(receiving_node_addr, Message.getjson("find_succ_for_id", self.id))
        if response is not None and response["subject"] == "set_your_succ":
            self.update_ith_finger(1, Address.get_address_from_string(response["payload"]))

            response = queryadd(self.finger_table[1], Message.getjson("get_your_pre"))
            if response is not None and response["subject"] == "my_pre":
                self.set_predecessor(Address.get_address_from_string(response["payload"]))

            self.notify(self.finger_table[1])



    def set_predecessor(self, addr):
        self.predecessor = addr
        print("Predecessor for {0} set to id {1}".format(self.id, hashadd(addr)))

    def update_ith_finger(self, pos, address):
        if isinstance(address, Address) == False and address is not None:
            address = Address.get_address_from_string(address)
        if pos == 1:
            print("Successor for {0} set to id {1}".format(self.id, hashadd(address)))
        if pos > 0 and pos <= 2 ** M:
            self.finger_table[pos] = address

    def get_successor(self):
        return self.finger_table[1]

    def delete_successor(self):
        succ = self.get_successor()
        if succ is None:
            return

        i = M
        for i in range(i, 0, -1):
            ith_finger = self.finger_table[i]
            if ith_finger is not None and ith_finger == succ:
                break

        for j in range(i, 0, -1):
            self.update_ith_finger(j, None)

        if self.predecessor is not None and self.predecessor == succ:
            self.set_predecessor(None)

        self.fillsuc()
        new_succ = self.get_successor()

        if (new_succ is None or new_succ == self.local_address)  and self.predecessor is not None and self.predecessor != self.local_address:
            pre = self.predecessor
            pre_pre = None
            while True:
                pre_pre = queryadd(pre, "get_your_pre")
                if pre_pre is not None and pre_pre["payload"] is None:
                    break

                if pre_pre == pre or pre_pre == self.local_address or pre_pre == new_succ:
                    break

                else:
                    pre = pre_pre

            self.update_ith_finger(1, pre)

    def fillsuc(self):
        succ = self.get_successor()
        if succ is None or succ == self.local_address:
            for i in range(2, M + 1):
                ith_finger = self.finger_table[i]
                if ith_finger is not None and isinstance(ith_finger, Address) == False and len(ith_finger) > 10:
                    ith_finger = Address.get_address_from_string(ith_finger)
                if ith_finger is not None and ith_finger != self.local_address:
                    # Push this value "up" in the table
                    for j in range(i-1, 0, -1):
                        self.update_ith_finger(j, ith_finger)
                    break


        new_succ = self.get_successor()
        if (new_succ is None or new_succ == self.local_address) and self.predecessor is not None and self.predecessor != self.local_address:
            self.update_ith_finger(1, self.predecessor)

        if (self.get_successor() is None and self.predecessor is None):
            self.update_ith_finger(1, self.local_address)

    def findsucc(self, search_id):
        if search_id is None:
            return

        if search_id == self.id:
            return self.get_successor()

        ret = self.get_successor()

        pre = self.findpredec(search_id)

        if pre is not None and pre != self.local_address:
            ret_q = queryadd(pre, Message.getjson("get_your_succ"))
            if ret_q is not None and ret_q["subject"] == "my_succ":
                ret = Address.get_address_from_string(ret_q["payload"])

        if ret is None:
            ret = self.local_address

        return ret


    def findpredec(self, search_id):
        if search_id is None:
            return

        ret = self.local_address
        ret_succ = self.get_successor()
        most_recently_alive = self.local_address
        ret_succ_offset = 0

        if ret_succ is not None:
            ret_succ_offset = find_offset(hashadd(ret), hashadd(ret_succ))

        search_id_offset = find_offset(self.id, search_id)

        while not (search_id_offset > 0 and search_id_offset <= ret_succ_offset):
            curr_node_temp = ret

            if ret == self.local_address:
                ret = self.closestprecedfinger(search_id)

            else:
                result_q  = queryadd(ret, Message.getjson("find_closest_p", search_id))
                if result_q is not None and result_q["subject"] == "closest_p":
                    result = None if result_q["payload"] is None else Address.get_address_from_string(result_q["payload"])
                else:
                    result = None

                if result is None:
                    ret = most_recently_alive
                    ret_succ_q = queryadd(ret, Message.getjson("get_your_succ"))
                    ret_succ = Address.get_address_from_string(ret_succ_q["payload"]) if ret_succ_q is not None and ret_succ_q["subject"] == "my_succ" else None
                    if ret_succ is None:
                        return self.local_address
                    continue

                elif result == ret:
                    return result

                else:
                    most_recently_alive = ret
                    ret_succ_q = queryadd(result, Message.getjson("get_your_succ"))
                    ret_succ = Address.get_address_from_string(ret_succ_q["payload"])
                    if ret_succ is not None:
                        ret = result
                    else:
                        ret_succ_q = queryadd(ret, Message.getjson("get_your_succ"))
                        ret_succ = Address.get_address_from_string(ret_succ_q["payload"])

                ret_succ_offset = find_offset(hashadd(ret), hashadd(ret_succ))
                search_id_offset = find_offset(hashadd(ret), search_id)

            if curr_node_temp == ret:
                break

        return ret


    def closestprecedfinger(self, search_id):
        if search_id is None:
            return

        search_id_offset = find_offset(self.id, search_id)

        for i in range(M, 0, -1):
            ith_finger = self.finger_table[i]
            if ith_finger is None:
                continue

            if isinstance(ith_finger, Address) == False and len(ith_finger) > 10:
                ith_finger = Address.get_address_from_string(ith_finger)
            else:
                continue
            ith_finger_id = hashadd(ith_finger)
            ith_finger_offset = find_offset(self.id, ith_finger_id)

            if ith_finger_offset > 0 and ith_finger_offset < search_id_offset:
                query = queryadd(ith_finger, Message.getjson("areyoualive"))
                if query["subject"] == "iamalive":
                    return ith_finger

                self.finger_table[i] = None

        return self.local_address


    def __eq__(self, other):
        return self.local_address == other.local_address

    def __hash__(self):
        return hash(id(self))


    def notify(self, successor_addr):
        if successor_addr != self.local_address:
             addresssend(successor_addr, Message.getjson("i_am_your_pre", str(self.local_address)))


    def notified(self, new_pre_addr):
        if self.predecessor is None or self.predecessor == self.local_address:
            self.set_predecessor(new_pre_addr)
        else:
            old_pre_id = hashadd(self.predecessor)
            this_id_offset = find_offset(old_pre_id, self.id)
            new_pre_offset = find_offset(old_pre_id, hashadd(new_pre_addr))
            if new_pre_offset > 0 and new_pre_offset < this_id_offset:
                self.set_predecessor(new_pre_addr)

    def sendFile(self, filename, hashValue, port):
        global filesList
        infoStr = filename + ":" + str(hashValue)
        soc = socket.socket()

        try:
                soc.connect(('127.0.0.1', port))
                send = "-f:" + infoStr
                send = send.encode()
                soc.send(send)
                time.sleep(0.2)
                msg = soc.recv(1024)
                msg = msg.decode("utf-8")
                if (msg == "done"):
                    f = open(filename, "rb")
                    l = f.read(1024)
                    while (l):
                        soc.send(l)
                        l = f.read(1024)
        finally:
                soc.close()

    def Filehash(filename):
        hash = hashlib.md5(filename.encode())
        Hash2 = hash.hexdigest()
        value = int(Hash2, 16)
        value = value % 9000
        filehash = int(value)

        return filehash



    def requestFile(port, filename):
        global filesList
        soc = socket.socket()
        try:
            soc.connect(('127.0.0.1', port))
            send = "-r:" + filename
            send = send.encode()
            soc.send(send)
            time.sleep(0.2)
            f = open(filename, 'wb')
            i = 0
            while (i):
                l = soc.recv(1024)
                f.write(l)
                if ((i % 100) == 0):
                    spr = spr + "."
                    print(spr)
                if not l:
                    break
                i = i + 1
            f.close()
        finally:
            soc.close()


if __name__ == "__main__":
    if (len(sys.argv) <2):
        ip_addr = "127.0.0.1"
        port = random.randint(50000, 65000)
    else:
        ip_addr = sys.argv[0]
        port = int(sys.argv[1])
    this_node = Node(ip_addr, port)
    this_node.start()