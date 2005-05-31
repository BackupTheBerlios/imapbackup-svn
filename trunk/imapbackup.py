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

import sys
import os
import socket
import imaplib
import time
import sha
import types
import string
import re
import ConfigParser
import logging, logging.handlers
import getopt

message_deliver_count = 0

# ----------------------------------------------------------------------------
class Log:
    def __call__(self):
        return self

    def __init__(self):
        self.__logger = logging.getLogger('imapbackup')
        self.__formatter = logging.Formatter('%(asctime)s %(message)s')
        self.__handlers = []

    def __add_handler(self, handler):
        self.__logger.addHandler(handler)
        self.__handlers.append(handler)

    def set_log_level(self, mode):
        """Set the logging level.

        Use logger.INFO, logger.WARN, logger.ERROR, ...
        """
        self.__logger.setLevel(mode)

    def remove_all_handlers(self):
        """Remove all registered log handlers.
        """
        for h in self.__handlers:
            self.__logger.removeHandler(h)
        self.__handlers = []

    def log_to_file(self, fname, exclusive=False):
        """Make the logger to log to a file.

        If the parameter 'exclusive' is True, than all other log handlers
        are removed.
        """
        if fname not in (''):
            if exclusive:
                self.remove_all_handlers()
            handler = logging.FileHandler(os.path.expanduser(fname))
            handler.setFormatter(self.__formatter)
            self.__add_handler(handler)

    def log_to_syslog(self, exclusive=False):
        """Make the logger to log to syslog.

        If the parameter 'exclusive' is True, than all other log handlers
        are removed.
        """
        if exclusive:
            self.remove_all_handlers()
        handler = logging.handlers.SysLogHandler()
        handler.setFormatter(self.__formatter)
        self.__add_handler(handler)

    def debug(self, msg):
        self.__logger.debug(msg)

    def info(self, msg):
        self.__logger.info(msg)

    def warn(self, msg):
        self.__logger.warn(msg)
    
    def error(self, msg):
        self.__logger.error(msg)

    def critical(self, msg):
        self.__logger.critical(msg)
        sys.exit()

# create singleton
Log = Log()


# ----------------------------------------------------------------------------
class Utils:
    def __call__(self):
        return self

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
        Log().debug('flags: %s --> aux: %s' % (flags, aux))
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

# create singleton
Utils = Utils()


# ----------------------------------------------------------------------------
class Configuration:
    def __init__(self, cfiles):
        self.__IMAPHOST = 'imapserver'
        self.__IMAPPORT = 'imapport'
        self.__IMAPUSER = 'imapuser'
        self.__IMAPPASSWORD = 'imappassword'
        self.__IMAPFILTER = 'imapfilter'
        self.__IMAPSSL = 'imapssl'
        self.__MAILDIR = 'maildir'
        self.__LOGGER = 'logger'
        self.__LOGFILE = 'logfile'
        self.__LOGLEVEL = 'loglevel'
        
        self.__cparser = ConfigParser.ConfigParser()

        if type(cfiles) != types.ListType: cfiles = [cfiles]
        def expand_user(path): return os.path.expanduser(path)

        Log().debug('config files: %s' % map(expand_user, cfiles))
        self.__cparser.read(map(expand_user, cfiles))

    def get_accounts(self):
        """Return list of all accounts.
        """
        return self.__cparser.sections()

    def get_host(self, account):
        """Return imap host.
        """
        try:
            return self.__cparser.get(account, self.__IMAPHOST)
        except:
            Log().critical('host for account %s not configured!' % account)

    def get_port(self, account):
        """Return optional parameter imap port.

        default return value: 993
        """
        try:
            return int(self.__cparser.get(account, self.__IMAPPORT))
        except:
            return 993

    def get_username(self, account):
        """Return imap username.
        """
        try:
            return self.__cparser.get(account, self.__IMAPUSER)
        except:
            Log().critical('username for account %s not configured!' % account)

    def get_password(self, account):
        """Return imap password.
        """
        try:
            return self.__cparser.get(account, self.__IMAPPASSWORD)
        except:
            Log().critical('password for account %s not configured!' % account)

    def get_maildir(self, account):
        """Return maildir path.
        """
        try:
            return self.__cparser.get(account, self.__MAILDIR)
        except:
            Log().critical('maildir for account %s not configured!' % account)

    def get_imapfilter(self, account):
        """Return optional imap filter string.

        default return value: None
        """
        try:
            return self.__cparser.get(account, self.__IMAPFILTER)
        except:
            return None

    def use_imapssl(self, account):
        """Return True or False for optional parameter 'imapssl'.

        default return value: True
        """
        try:
            if str.lower(self.__cparser.get(account, self.__IMAPSSL)) == 'false':
                return False
            else:
                return True
        except:
            return True

    def get_logger(self, account):
        """Return optional parameter logger.

        default return value: none
        """
        try:
            return self.__cparser.get(account, self.__LOGGER)
        except:
            return 'syslog'

    def get_log_file(self, account):
        """Return file to log to.
        """
        try:
            return self.__cparser.get(account, self.__LOGFILE)
        except:
            Log().critical('logfile for account %s not configured!' % account)

    def get_log_level(self, account):
        """Return optional parameter log level.

        default return value: logger.ERROR
        """
        try:
            lvl = str.lower(self.__cparser.get(account, self.__LOGLEVEL))
            if lvl == 'debug': return logging.DEBUG
            elif lvl == 'info': return logging.INFO
            elif lvl == 'warning': return logging.WARNING
            elif lvl == 'error': return logging.ERROR
            elif lvl == 'critical': return logging.CRITICAL
        except:
            return logging.ERROR

# ----------------------------------------------------------------------------
class IMAPException(Exception): pass
class IMAP:
    def __init__(self, host=None, port=None, user=None, password=None, ssl=True):
        self.__connection = None
        self.__regex_folderstr = re.compile('^\((.*)\) +"(.*)" +"(.*)"$')
        self.__regex_uid = re.compile('UID (.*) BODY')
        self.__regex_flags = re.compile('FLAGS (.*) BODY')

        if host and port and user and password:
            self.open(host, port, user, password, ssl)

    def open(self, host, port, user, password, ssl=True):
        """Try to open the imap connection.
        """
        try:
            if ssl:
                self.__connection = imaplib.IMAP4_SSL(host, port)
            else:
                self.__connection = imaplib.IMAP4(host, port)
            self.__connection.login(user, password)
        except Exception, e:
            raise IMAPException('can not connect to \'%s:%d\': %s' % (host, port, str(e)))

    def __check_connection(self):
        """Check the imap connection.

        If the connection check fail, exit with an error.
        """
        try:
            self.__connection.noop()
        except:
            # something went wrong
            raise IMAPException('not connected to server!')

    def get_folders(self, filter=None):
        """Return a list with all imap folders.
        """
        self.__check_connection()
    
        ret = []

        try:
            status, flist = self.__connection.list()
        except Exception, e:
            raise IMAPException('can not get folder list: %s' % str(e))

        if status != 'OK':
            Log().warn('imap.list() return: %s' % flist[0])
        
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
            Log().warn('imap.search() return: %s' % flist[0])

        uid_list = {}
        for mnum in mnum_list[0].split():
            status, data = self.__connection.fetch(mnum, '(UID BODY.PEEK[HEADER])')
            uid = self.__regex_uid.search(data[0][0]).group(1)
            hd = Utils().hash_message_header(data[0][1]).hexdigest()
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
            Log().warn('imap.search() return: %s' % flist[0])

        status, data = self.__connection.fetch(mnum[0], '(FLAGS BODY.PEEK[])')
        flags = self.__regex_flags.search(data[0][0]).group(1)
        return [flags, data[0][1]]


# ----------------------------------------------------------------------------
class MaildirException(Exception): pass
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
        self.__basedir = os.path.expanduser(basedir)
        try:
            if create == True:
                if not os.path.isdir(self.__basedir):
                    os.mkdir(self.__basedir)
        except Exception, e:
            raise MaildirException('can not create basedir \'%s\': %s' % (self.__basedir, e))

        # raise an exception, if basedir does not exist
        if not os.path.isdir(self.__basedir):
            raise MaildirException('basedir \'%s\' does not exist' % self.__basedir)

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
            
        fname = Utils().gen_filename()
        fname_tmp = os.path.join(folder, 'tmp', fname)

        if Utils().message_seen(flags):
            fname_dst = os.path.join(folder, 'cur', fname + Utils().gen_filename_aux(flags))
        else:
            fname_dst = os.path.join(folder, 'new', fname)

        try:
            fd = open(fname_tmp, 'w')
            fd.write(message)
            fd.close()
        except Exception, e:
            raise MaildirException('can not write message \'%s\'' % fname_tmp)

        os.rename(fname_tmp, fname_dst)
        Log().debug('write message "%s"' % fname_dst)


    def remove_from_index(self, folder, hd):
        """Remove index entry.
        """
        if not folder.startswith(self.__basedir):
            folder = os.path.join(self.__basedir, folder)
        folder = folder.rstrip('/')

        if self.__sha1_header_cache.has_key(folder):
            if self.__sha1_header_cache[folder].has_key(hd):
                del self.__sha1_header_cache[folder][hd]

    def remove_leftover_messages(self):
        """Remove files, which are leftover from updating.
        """
        for i in self.__sha1_header_cache.keys():
            for j in self.__sha1_header_cache[i].keys():
                for f in self.__sha1_header_cache[i][j]:
                    os.remove(os.path.join(i, f))
                    Log().debug('remove message "%s"' % os.path.join(i, f))

    def __is_maildir_folder(self, folder):
        """Return True if the folder is a maildir folder.

        Test if the folder contains the three folders 'new',
        'cur' and 'tmp'.
        """
        if not folder.startswith(self.__basedir):
            folder = os.path.join(self.__basedir, folder)
        return os.path.isdir(os.path.join(folder, 'new')) and \
               os.path.isdir(os.path.join(folder, 'cur')) and \
               os.path.isdir(os.path.join(folder, 'tmp'))

    def __get_folder_list(self, folder=None):
        """Return a list of valid mail folders.
        """
        if folder == None: folder = self.__basedir
        if not folder.startswith(self.__basedir):
            folder = os.path.join(self.__basedir, folder)

        flist = [folder]
        for fo in os.listdir(folder):
            if os.path.isdir(os.path.join(folder,fo)) and self.__is_maildir_folder(fo):
                flist.append(os.path.join(folder,fo))

        return flist


    def __get_message_list(self, folder):
        """Return a list of mail filenames for the given folder.
        """
        mlist = []

        if folder == None: folder = self.__basedir
        if not folder.startswith(self.__basedir):
            folder = os.path.join(self.__basedir, folder)

        try:
            for mdfolder in ['new', 'cur', 'tmp']:
                if os.path.isdir(os.path.join(folder, mdfolder)):
                    for i in os.listdir(os.path.join(folder, mdfolder)):
                        if os.path.isfile(os.path.join(folder, mdfolder, i)):
                            mlist.append([mdfolder, i])
        except Exception, e:
            raise MaildirException('can not get message list for folder \'%s\': %s' % (folder, e))
        return mlist


    def __index_messages(self, folder=None):
        """Index all messages in the maildir.
        """
        ret = {}

        for foname in self.__get_folder_list(folder):
            foname = foname.rstrip('/')
            self.__sha1_header_cache[foname]={}
            for fname in self.__get_message_list(foname):
                rfname = os.path.join(foname, fname[0], fname[1])
                sfname = os.path.join(fname[0], fname[1])

                lines = ''
                try:
                    file = open(rfname, 'r')
                    # only get header
                    for line in file:
                        if len(line) <= 2:
                            break
                        lines += line
                    file.close()
                except Exception, e:
                    raise MaildirException('can not index message \'%s\': ' % (rfname, e))

                hd = Utils().hash_message_header(lines).hexdigest()
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
            Log().debug('create folder "%s"' % folder)
        return ret


# ----------------------------------------------------------------------------
class Worker:
    def __init__(self):
        self.__config = None
        self.__config_file = '~/.imapbackuprc'
        self.__list_folders = False
        self.__account = 'all'

        self.__parse_cmdl()
        self.__init_config()

    def __show_syntax(self):
        print('imapbackup.py [options]')
        print('   options:')
        print('     -h --help            print this message')
        print('     -a --account         select an account (def: all)')
        print('     -c --config-file     use another config file (def: ~/.imapbackuprc)')
        print('     -l --list-folders    list folders in selected accounts')

    def __parse_cmdl(self):
        """
        """
        try:
            opts, args = getopt.getopt(sys.argv[1:], \
                "ha:c:l:", \
                ["help", "account=", "config-file=", "list-folders"])
        except getopt.GetoptError, e:
            print('error: %s' % e)
            self.__show_syntax()
            sys.exit(2)
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                self.__show_syntax()
                sys.exit(3)
            elif opt in ("-a", "--account"):
                self.__account = arg
            elif opt in ("-c", "--config-file"):
                self.__config_file = arg
            elif opt in ("-l", "--list-folders"):
                self.__list_folders = True

    def __init_config(self):
        """Initialize the configuration.
        """
        self.__config_file = os.path.expanduser(self.__config_file)
        if os.path.isfile(self.__config_file):
            self.__config = Configuration(self.__config_file)
        else:
            print('can not open config file: %s' % self.__config_file)
            sys.exit(-1)

    def __config_logger(self, account):
        """Configures the logger singelton for the given account.
        """
        Log().remove_all_handlers()
        for logger in self.__config.get_logger(account).split(', '):
            if str.lower(logger) == 'syslog':
                Log().log_to_syslog()
            elif str.lower(logger) == 'file':
                Log().log_to_file(self.__config.get_log_file(account))
        Log().set_log_level(self.__config.get_log_level(account))

    def run(self):
        if self.__list_folders:
            if str.lower(self.__account) == 'all':
                self.list_all_imap_folders()
            else:
                self.list_imap_folders(self.__account)
        else:
            if str.lower(self.__account) == 'all':
                self.backup_all()
            else:
                self.backup(self.__account)

    def list_all_imap_folders(self):
        for account in self.__config.get_accounts():
            self.list_imap_folders(account)

    def list_imap_folders(self, account):
        try:
            self.__config_logger(account)
            imap = IMAP(self.__config.get_host(account),
                        self.__config.get_port(account),
                        self.__config.get_username(account),
                        self.__config.get_password(account),
                        self.__config.use_imapssl(account))

            filter = self.__config.get_imapfilter(account)
            print('[%s]' % account)
            for folder in imap.get_folders(filter):
                print '-> %s' % folder
            print
        except IMAPException, e:
            Log().error('imap error: ' % e)
        except Exception, e:
            Log().error('error: ' % e)

    def backup_all(self):
        for account in self.__config.get_accounts():
            self.backup(account)

    def backup(self, account):
        try:
            self.__config_logger(account)
            maildir = Maildir(self.__config.get_maildir(account), True)
            imap = IMAP(self.__config.get_host(account),
                        self.__config.get_port(account),
                        self.__config.get_username(account),
                        self.__config.get_password(account))
            
            fo_filter = self.__config.get_imapfilter(account)
            for folder in imap.get_folders(fo_filter):
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

            maildir.remove_leftover_messages()
        except IMAPException, e:
            Log().error('imap error: ' % e)
        except Exception, e:
            Log().error('error: ' % e)


# ----------------------------------------------------------------------------
if __name__ == "__main__":
    Worker().run()
