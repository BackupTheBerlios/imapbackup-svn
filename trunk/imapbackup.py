#!/usr/bin/python
#
# Copyright 2005 Rico Schiekel
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
# 
# $Id$

import os, sys
import socket, imaplib
import time, sha, types
import string, re
import ConfigParser

verbose = True
message_deliver_count = 0

def info(msg):
    if verbose:
        sys.stderr.write('info: ' + str(msg) + '\n')

def warn(msg):
    sys.stderr.write('warning: ' + str(msg) + '\n')

def error(msg):
    sys.exit('error: ' + str(msg))

class Configuration:
    def __init__(self, cfiles):
        self.__HOST = 'host'
        self.__PORT = 'port'
        self.__USERNAME = 'username'
        self.__PASSWORD = 'password'
        self.__MAILDIR = 'maildir'
        self.__IMAPFILTER = 'imapfilter'
        
        self.__cparser = ConfigParser.ConfigParser()

        if type(cfiles) != types.ListType: cfiles = [cfiles]
        def expand_user(path): return os.path.expanduser(path)

        self.__cparser.read(map(expand_user, cfiles))

    def get_accounts(self):
        return self.__cparser.sections()

    def get_host(self, account):
        try:
            return self.__cparser.get(account, self.__HOST)
        except:
            error('host for account %s not configured!' % account)

    def get_port(self, account):
        try:
            return int(self.__cparser.get(account, self.__PORT))
        except:
            error('port for account %s not configured!' % account)

    def get_username(self, account):
        try:
            return self.__cparser.get(account, self.__USERNAME)
        except:
            error('username for account %s not configured!' % account)

    def get_password(self, account):
        try:
            return self.__cparser.get(account, self.__PASSWORD)
        except:
            error('password for account %s not configured!' % account)

    def get_maildir(self, account):
        try:
            return self.__cparser.get(account, self.__MAILDIR)
        except:
            error('maildir for account %s not configured!' % account)

    def get_imapfilter(self, account):
        try:
            return self.__cparser.get(account, self.__IMAPFILTER)
        except:
            return None

class Utils:
    def __init__(self):
        self.__regex_from = re.compile('^from: .*$', re.IGNORECASE)
        self.__regex_to = re.compile('^to: .*$', re.IGNORECASE)
        self.__regex_subject = re.compile('^subject: .*$', re.IGNORECASE)
        self.__regex_msgid = re.compile('^message-id: .*$', re.IGNORECASE)
        self.__regex_date = re.compile('^date: .*$', re.IGNORECASE)
        self.__regex_received = re.compile('^received: .*$', re.IGNORECASE)
        self.__regex_xorgto = re.compile('^x-original-to: .*$', re.IGNORECASE)
        self.__regex_delivto = re.compile('^delivered-to: .*$', re.IGNORECASE)
        self.__regex_returnpath = re.compile('^return-path: .*$', re.IGNORECASE)
        self.__regex_msg_seen = re.compile('.*\Seen.*')
        self.__regex_msg_answerd = re.compile('.*\Answered.*')
        self.__regex_msg_flagged = re.compile('.*\Flagged.*')
        self.__regex_msg_deleted = re.compile('.*\Deleted.*')
        self.__regex_msg_draft = re.compile('.*\Draft.*')
        self.__regex_whitespaces = re.compile(' |\t')

    def hash_message_header(self, message):
        """Generate an sha1 checksum of the message header.
        """
        hd_obj = sha.new()
        for line in message.splitlines():
            if len(line) == 0:
                # only scan the header
                break
            if self.__regex_from.search(line):
                hd_obj.update(self.__regex_whitespaces.sub('', line))
            elif self.__regex_to.search(line):
                hd_obj.update(self.__regex_whitespaces.sub('', line))
            elif self.__regex_subject.search(line):
                hd_obj.update(self.__regex_whitespaces.sub('', line))
            elif self.__regex_msgid.search(line):
                hd_obj.update(self.__regex_whitespaces.sub('', line))
            elif self.__regex_date.search(line):
                hd_obj.update(self.__regex_whitespaces.sub('', line))
            elif self.__regex_received.search(line):
                hd_obj.update(self.__regex_whitespaces.sub('', line))
            elif self.__regex_xorgto.search(line):
                hd_obj.update(self.__regex_whitespaces.sub('', line))
            elif self.__regex_delivto.search(line):
                hd_obj.update(self.__regex_whitespaces.sub('', line))
            elif self.__regex_returnpath.search(line):
                hd_obj.update(self.__regex_whitespaces.sub('', line))
        return hd_obj

    def gen_filename(self):
        t = str(time.time()).split(".")
        global message_deliver_count
        message_deliver_count += 1
        return "%s.M%sP%dQ%d.%s" % (t[0], t[1], os.getpid(), message_deliver_count, socket.gethostname())

    def gen_filename_aux(self, flags):
        aux = ''
        if self.message_seen(flags):
            aux += 'S'
        if self.message_answerd(flags):
            aux += 'R'
        if self.message_flagged(flags):
            aux += 'F'
        if self.message_deleted(flags):
            aux += 'T'
        if self.message_draft(flags):
            aux += 'D'
        if len(aux) > 0:
            aux = ',' + aux
        return aux

    def message_seen(self, flags):
        return self.__regex_msg_seen.match(flags)
    def message_answerd(self, flags):
        return self.__regex_msg_answerd.match(flags)
    def message_flagged(self, flags):
        return self.__regex_msg_flagged.match(flags)
    def message_deleted(self, flags):
        return self.__regex_msg_deleted.match(flags)
    def message_draft(self, flags):
        return self.__regex_msg_draft.match(flags)


class IMAP:
    def __init__(self, host=None, port=None, user=None, password=None):
        self.__connection = None
        self.__regex_folderstr = re.compile('^\((.*)\) +"(.*)" +"(.*)"$')
        self.__regex_uid = re.compile('UID (.*) BODY')
        self.__regex_flags = re.compile('FLAGS (.*) BODY')

        if host and port and user and password:
            self.open(host, port, user, password)

    def open(self, host, port, user, password):
        """Try to open the imap connection.
        """
        try:
            self.__connection = imaplib.IMAP4_SSL(host, port)
            self.__connection.login(user, password)
        except Exception, e:
            error('can not connect to \'%s:%d\': %s' % (host, port, str(e)))

    def __check_connection(self):
        """Check the imap connection.

        If the connection check fail, exit with an error.
        """
        try:
            self.__connection.noop()
        except:
            # something went wrong
            error('not connected to server!')


    def get_folders(self, filter=None):
        """Return a list with all imap folders.
        """
        self.__check_connection()
    
        ret = []

        try:
            status, flist = self.__connection.list()
        except Exception, e:
            error('can not get folder list: %s' % str(e))

        if status != 'OK':
            warn('imap.list() return: %s' % flist[0])
        
        for fostr in flist:
            ro = self.__regex_folderstr.search(fostr)
            if filter:
                if re.compile(str(filter)).search(ro.group(3)):
                    ret.append(ro.group(3))
            else:
                ret.append(ro.group(3))
        return ret

    def get_messages(self, folder):
        """Return a hash with all message uid's for the given folder.

        The uid is used as hash key, while the sha1 hex digest from the
        header is used as hash value.
        """
        self.__check_connection()

        self.__connection.select(folder)
        status, mnum_list = self.__connection.search(None, 'ALL')
        
        if status != 'OK':
            warn('imap.search() return: %s' % flist[0])

        utils = Utils()
        uid_list = {}
        for mnum in mnum_list[0].split():
            status, data = self.__connection.fetch(mnum, '(UID BODY.PEEK[HEADER])')
            uid = self.__regex_uid.search(data[0][0]).group(1)
            hd = utils.hash_message_header(data[0][1]).hexdigest()
            uid_list[uid] = hd

        return uid_list

    def get_message_sha1(self, folder, uid):
        """Return the sha1 hex digest for the whole message.
        """
        return sha.new(self.get_message(folder, uid)).hexdigest()

    def get_message(self, folder, uid):
        """Return the status and the message body for the given uid in the given folder.

        Return: [str flags, str message]
        """
        self.__check_connection()

        self.__connection.select(folder)
        status, mnum = self.__connection.search(None, 'UID', str(uid))
        
        if status != 'OK':
            warn('imap.search() return: %s' % flist[0])

        status, data = self.__connection.fetch(mnum[0], '(FLAGS BODY.PEEK[])')
        flags = self.__regex_flags.search(data[0][0]).group(1)
        return [flags, data[0][1]]


class Maildir:
    def __init__(self, basedir=None, create=False):
        self.__basedir=''
        self.__sha1_header_cache={}
        if basedir:
            self.open(basedir, create)

    def open(self, basedir, create=False):
        """Open the maildir folder and index all existing messages.

        If 'create' is true and 'basedir' is no maildir, than an new 
        maildir will be created.
        """
        self.__basedir = basedir
        if create == True:
            if not os.path.isdir(self.__basedir):
                os.mkdir(self.__basedir)

        self.__index_messages()


    def has_message_header(self, folder, hd):
        """Search for a mail given the sha1 hex digest from the header.
        """
        if not folder.startswith(self.__basedir):
            folder = os.path.join(self.__basedir, folder)
        folder = folder.rstrip('/')

        if self.__sha1_header_cache.has_key(folder):
            return self.__sha1_header_cache[folder].has_key(hd)
            
        return False


    def create_folder(self, folder):
        """Create a new maildir folder.

        Does nothing, if the folder exists.
        """
        if not folder.startswith(self.__basedir):
            folder = os.path.join(self.__basedir, folder)

        return self.__create_folder(folder)


    def write_message(self, folder, message, flags):
        """Write a message in the given folder of the maildir.
        """
        if not folder.startswith(self.__basedir):
            folder = os.path.join(self.__basedir, folder)
            
        utils = Utils()
        fname = utils.gen_filename()
        fname_tmp = os.path.join(folder, 'tmp', fname)

        if utils.message_seen(flags):
            fname_dst = os.path.join(folder, 'cur', fname + utils.gen_filename_aux(flags))
        else:
            fname_dst = os.path.join(folder, 'new', fname)

        fd = open(fname_tmp, 'w')
        fd.write(message)
        fd.close()

        os.rename(fname_tmp, fname_dst)
        info('[Maildir] write message "%s"' % fname_dst)


    def remove_from_index(self, folder, hd):
        """Remove index entry.
        """
        if not folder.startswith(self.__basedir):
            folder = os.path.join(self.__basedir, folder)
        folder = folder.rstrip('/')

        if self.__sha1_header_cache.has_key(folder):
            if self.__sha1_header_cache[folder].has_key(hd):
                del self.__sha1_header_cache[folder][hd]

    def get_leftover_messages(self):
        """Return file names, which are leftover from updating.
        """
        ret = []
        for i in self.__sha1_header_cache.keys():
            for j in self.__sha1_header_cache[i].keys():
                for f in self.__sha1_header_cache[i][j]:
                    ret.append(os.path.join(i, f))
        return ret

    def __get_folder_list(self, folder=None):
        if folder == None: folder = self.__basedir
        if not folder.startswith(self.__basedir):
            folder = os.path.join(self.__basedir, folder)

        flist = [folder]
        for i in os.listdir(folder):
            if os.path.isdir(os.path.join(folder,i)) and i[0] == '.':
                flist.append(os.path.join(folder,i))

        return flist


    def __get_message_list(self, folder):
        mlist = []

        if folder == None: folder = self.__basedir
        if not folder.startswith(self.__basedir):
            folder = os.path.join(self.__basedir, folder)

        for mdfolder in ['new', 'cur', 'tmp']:
            if os.path.isdir(os.path.join(folder, mdfolder)):
                for i in os.listdir(os.path.join(folder, mdfolder)):
                    if os.path.isfile(os.path.join(folder, mdfolder, i)):
                        mlist.append([mdfolder, i])
        return mlist


    def __index_messages(self, folder=None):
        ret = {}

        utils = Utils()
        for foname in self.__get_folder_list(folder):
            foname = foname.rstrip('/')
            self.__sha1_header_cache[foname]={}
            for fname in self.__get_message_list(foname):
                rfname = os.path.join(foname, fname[0], fname[1])
                sfname = os.path.join(fname[0], fname[1])

                lines = ''
                file = open(rfname, 'r')
                # only get header
                for line in file:
                    if len(line) <= 2:
                        break
                    lines += line
                file.close()

                hd = utils.hash_message_header(lines).hexdigest()
                if self.__sha1_header_cache[foname].has_key(hd):
                    self.__sha1_header_cache[foname][hd].append(sfname)
                else:
                    self.__sha1_header_cache[foname][hd] = [sfname]

        return ret.keys()


    def __create_folder(self, folder):
        """Create an maildir folder if necessary.

        Return True if the folder was created, or False
        if the folder exists.
        """
        ret = False
        if not os.path.isdir(folder):
            os.mkdir(folder)
            ret = True
        if not os.path.isdir(os.path.join(folder, 'tmp')):
            os.mkdir(os.path.join(folder, 'tmp'))
            ret = True
        if not os.path.isdir(os.path.join(folder, 'cur')):
            os.mkdir(os.path.join(folder, 'cur'))
            ret = True
        if not os.path.isdir(os.path.join(folder, 'new')):
            os.mkdir(os.path.join(folder, 'new'))
            ret = True
        if ret:
            info('[Maildir] create folder "%s"' % folder)
        return ret

class Worker:
    def __init__(self, config):
        self.__config = config

    def backup_all(self):
        for account in self.__config.get_accounts():
            self.backup(account)

    def list_imap_folders(self, account):
        imap = IMAP(self.__config.get_host(account),
                    self.__config.get_port(account),
                    self.__config.get_username(account),
                    self.__config.get_password(account))

        filter = self.__config.get_imapfilter(account)
        for folder in imap.get_folders(filter):
            print '-> %s' % folder

    def backup(self, account):
        utils = Utils()
        
        maildir = Maildir(self.__config.get_maildir(account), True)
        imap = IMAP(self.__config.get_host(account),
                    self.__config.get_port(account),
                    self.__config.get_username(account),
                    self.__config.get_password(account))
        
        for folder in imap.get_folders():
            # create folder if needed
            cf = maildir.create_folder(folder)
        
            mlist = imap.get_messages(folder)
            for uid, hhd in mlist.iteritems():
                has_msg = maildir.has_message_header(folder, hhd)
                if cf or not has_msg:
                    # folder was newly created and header not in maildir index
                    # so save message
                    flags, body = imap.get_message(folder, uid)
                    maildir.write_message(folder, body, flags)
                else:
                    maildir.remove_from_index(folder, hhd)

        for fname in maildir.get_leftover_messages():
            info('[Worker] remove message "%s"' % fname)
            os.remove(fname)

if __name__ == "__main__":
    cfg = Configuration('~/work/imapbackup/imapbackuprc')
    w = Worker(cfg)
    w.backup_all()
    # w.list_imap_folders('')
