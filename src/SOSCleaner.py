# Copyright (C) 2013  Jamie Duncan (jduncan@redhat.com)

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# File Name : sos-gov.py
# Creation Date : 10-01-2013
# Created By : Jamie Duncan
# Last Modified : Wed 25 Jun 2014 08:51:51 PM EDT
# Purpose : an sosreport scrubber

import os
import re
import sys
import magic
from time import strftime, gmtime
import shutil
import struct, socket
import tempfile
import logging
import tarfile

class SOSCleaner:
    '''
    A class to parse through an sosreport and begin the cleaning process required in many industries
    Parameters:
    debug - will generate add'l output to STDOUT. defaults to no
    reporting - will post progress and overall statistics to STDOUT. defaults to yes
    '''
    def __init__(self, options, sosreport, loglevel='INFO', reporting=True):

        self._check_uid()   #make sure it's soscleaner is running as root
        self.name = 'soscleaner'
        self.version = '0.1'
        self.loglevel = loglevel
        self.reporting = reporting
        self.ip_db = {}
        self.start_ip = '10.230.230.1'
        self.hn_db = {}
        self.hostname_count = 0
        self.domain = 'example.com'
        self.loglevel = loglevel
        self.magic = magic.open(magic.MAGIC_NONE)
        # required for compression type magic patterns
        self.magic.load()
        #this handles all the extraction and path creation
        self.report, self.origin_path, self.dir_path, self.session, self.logfile = self._prep_environment(sosreport)
        self._get_disclaimer()
        self._make_dest_env()   #create the working directory
        self.hostname, self.domainname, self.is_fqdn = self._get_hostname()

    def _check_uid(self):
        if os.getuid() != 0:
            raise Exception("You Must Execute soscleaner As Root")

    def _skip_file(self, d, files):
        '''
        The function passed into shutil.copytree to ignore certain patterns and filetypes
        Currently Skipped
        Directories - handled by copytree
        Symlinks - handled by copytree
        Write-only files (stuff in /proc)
        Binaries (can't scan them)
        '''
        skip_list = []
        for f in files:
            f_full = os.path.join(d, f)
            if not os.path.isdir(f_full):
                if not os.path.islink(f_full):
                    mode = oct(os.stat(f_full).st_mode)[-3:]
                    # executing as root makes this first if clause useless.
                    # i thought i'd already removed it. - jduncan
                    if mode == '200' or mode == '444' or mode == '400':
                        skip_list.append(f)
                    if self.magic.buffer(f_full) == 'data':
                        skip_list.append(f)

        return skip_list

    def _start_logging(self, filename):
        #will get the logging instance going
        loglevel_config = 'logging.%s' % self.loglevel

        #i'd like the stdout to be under another logging name than 'con_out'
        console_log_level = 25  #between INFO and WARNING
        logging.addLevelName(console_log_level, "CONSOLE")

        def con_out(self, message, *args, **kws):
            self._log(console_log_level, message, args, **kws)

        logging.Logger.con_out = con_out

        logging.basicConfig(filename=filename,
            level=eval(loglevel_config),
            format='%(asctime)s %(name)s %(levelname)s: %(message)s',
            datefmt = '%m-%d %H:%M:%S'
            )
        console = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s: %(message)s', '%m-%d %H:%M:%S')
        console.setFormatter(formatter)
        console.setLevel(console_log_level)
	self.logger = logging.getLogger(__name__)
        self.logger.addHandler(console)

        self.logger.con_out("Log File Created at %s" % filename)

    def _prep_environment(self, path):

        #we set up our various needed directory structures, etc.
        timestamp = strftime("%Y%m%d%H%M%S", gmtime())
        origin_path = "/tmp/soscleaner-origin-%s" % timestamp
        dir_path = "/tmp/soscleaner-%s" % timestamp
        session = "soscleaner-%s" % timestamp
        logfile = "/tmp/%s.log" % session

        self._start_logging(logfile)

        self.logger.con_out("Beginning SOSReport Extraction")
        compression_sig = self.magic.file(path).lower()
        if 'directory' in compression_sig:
            self.logger.info('%s appears to be a %s - continuing', path, compression_sig)
            return path, origin_path, dir_path, session, logfile

        elif 'compressed data' in compression_sig:
            if compression_sig == 'xz compressed data':
                #This is a hack to account for the fact that the tarfile library doesn't
                #handle lzma (XZ) compression until version 3.3 beta
                try:
                    self.logger.info('Data Source Appears To Be LZMA Encrypted Data - decompressing into %s', origin_path)
                    self.logger.info('LZMA Hack - Creating %s', origin_path)
                    os.system('mkdir %s' % origin_path)
                    os.system('tar -xJf %s -C %s' % (path, origin_path))
                    return_path = os.path.join(origin_path, os.listdir(origin_path)[0])

                    return return_path, origin_path, dir_path, session, logfile

                except Exception,e:
                    self.logger.exception(e)
                    raise Exception('DecompressionError, Unable to decrypt LZMA compressed file %s', path)

            else:
                p = tarfile.open(path, 'r')

                self.logger.info('Data Source Appears To Be %s - decompressing into %s', compression_sig, origin_path)
                try:
                    p.extractall(origin_path)
                    return_path = os.path.join(origin_path, os.path.commonprefix(p.getnames()))

                    return return_path, origin_path, dir_path, session, logfile

                except Exception, e:
                    self.logger.exception(e)
                    raise Exception("DeCompressionError: Unable to De-Compress %s into %s", path, origin_path)
        else:
            raise Exception('CompressionError: Unable To Determine Compression Type')

    def _sub_ip(self, line):
        '''
        This will substitute an obfuscated IP for each instance of a given IP in a file
        This is called in the self._clean_line function, along with user _sub_* functions to scrub a given
        line in a file.
        It scans a given line and if an IP exists, it obfuscates the IP using _ip2db and returns the altered line
        '''
        try:
            pattern = r"(((\b25[0-5]|\b2[0-4][0-9]|\b1[0-9][0-9]|\b[1-9][0-9]|\b[1-9]))(\.(\b25[0-5]|\b2[0-4][0-9]|\b1[0-9][0-9]|\b[1-9][0-9]|\b[0-9])){3})"
            ips = [each[0] for each in re.findall(pattern, line)]
            if len(ips) > 0:
                for ip in ips:
                    new_ip = self._ip2db(ip)
                    self.logger.debug("Obfuscating IP - %s > %s", ip, new_ip)
                    line = line.replace(ip, new_ip)
            return line
        except Exception,e:
            self.logger.exception(e)
            raise Exception('SubIPError: Unable to Substitute IP Address - %s', ip)

    def _get_disclaimer(self):
        #prints a disclaimer that this isn't an excuse for manual or any other sort of data verification

        self.logger.con_out("%s - %s" % (self.name, self.version))
        self.logger.con_out("%s is a tool to help obfuscate sensitive information from an existing sosreport." % self.name)
        self.logger.con_out("Please review the content before passing it along to any third party.")

    def _create_reports(self):
        '''
        this will take the obfuscated ip and hostname databases and output csv files
        '''
        try:
            ip_report_name = "/tmp/%s-ip.csv" % self.session
            self.logger.con_out('Creating IP Report - %s', ip_report_name)
            ip_report = open(ip_report_name, 'w')
            ip_report.write('Obfuscated IP,Original IP\n')
            for k,v in self.ip_db.items():
                ip_report.write('%s,%s\n' %(self._int2ip(k),self._int2ip(v)))
            ip_report.close()
            self.logger.info('Completed IP Report')

            self.ip_report = ip_report_name
        except Exception,e:
            self.logger.exception(e)
            raise Exception('CreateReport Error: Error Creating IP Report')
        try:
            hn_report_name = "/tmp/%s-hostname.csv" % self.session
            self.logger.con_out('Creating Hostname Report - %s', hn_report_name)
            hn_report = open(hn_report_name, 'w')
            hn_report.write('Obfuscated Hostname,Original Hostname\n')
            for k,v in self.hn_db.items():
                hn_report.write('%s,%s\n' %(k,v))
            hn_report.close()
            self.logger.info('Completed Hostname Report')

            self.hn_report = hn_report_name
        except Exception,e:
            self.logger.exception(e)
            raise Exception('CreateReport Error: Error Creating Hostname Report')

    def _sub_hostname(self, line):
        '''
        This will replace the exact hostname and all instances of the domain name with the obfuscated alternatives.
        Example:
        '''
        try:
            if self.is_fqdn:
                regex = re.compile(r'\w*\.%s' % self.domainname)
                hostnames = [each for each in regex.findall(line)]
                if len(hostnames) > 0:
                    for hn in hostnames:
                        new_hn = self._hn2db(hn)
                        self.logger.debug("Obfuscating FQDN - %s > %s", hn, new_hn)
                        line = line.replace(hn, new_hn)
        except Exception,e:
            self.logger.exception(e)
            raise Exception('SubHostnameError: Unable to Substitute FQDN')

        '''
        logs like secure have a non-FQDN hostname entry on almost every line.
        So we will always run this bit of code to clean up as much as possibe, in addition
        to searching for all of the FQDNs that we know exist.
        we don't have an FQDN, so we will only do a 1:1 replacement for the hostname
        '''

        try:
            new_hn = self._hn2db(self.hostname)
            self.logger.debug("Obfuscating Non-FQDN - %s > %s", self.hostname, new_hn)
            line = line.replace(self.hostname, new_hn)
        except Exception,e:
            self.logger.exception(e)
            raise Exception('SubHostnameError: Unable to Substitute Non-FQDN')

        return line

    def _make_dest_env(self):
        '''
        This will create the folder in /tmp to store the sanitized files and populate it using shutil
        These are the files that will be scrubbed
        '''
        try:
            shutil.copytree(self.report, self.dir_path, symlinks=True, ignore=self._skip_file)
        except Exception, e:
            self.logger.exception(e)
            raise Exception("DestinationEnvironment Error: Cannot Create Destination Environment")

    def _create_archive(self):
        '''This will create a tar.gz compressed archive of the scrubbed directory'''
        try:
            archive = "/tmp/%s.tar.gz" % self.session
            self.archive_path = archive
            self.logger.con_out('Starting Archiving Process - Creating %s', archive)
            t = tarfile.open(archive, 'w:gz')
            for dirpath, dirnames, filenames in os.walk(self.dir_path):
                for f in filenames:
                    f_full = os.path.join(dirpath, f)
                    f_archive = f_full.replace('/tmp','')
                    self.logger.debug('adding %s to %s archive', f_archive, archive)
                    t.add(f_full, arcname=f_archive)
        except Exception,e:
            self.logger.exception(e)
            raise Exception('CreateArchiveError: Unable to create Archive')
        self._clean_up()
        self.logger.con_out('Archiving Complete')
        self.logger.con_out('SOSCleaner Complete')
        t.add(self.logfile, arcname=self.logfile.replace('/tmp',''))
        t.close()

    def _clean_up(self):
        '''This will clean up origin directories, etc.'''
        self.logger.info('Beginning Clean Up Process')
        try:
            if self.origin_path:
                self.logger.info('Removing Origin Directory - %s', self.origin_path)
                shutil.rmtree(self.origin_path)
            self.logger.info('Removing Working Directory - %s', self.dir_path)
            shutil.rmtree(self.dir_path)
            self.logger.info('Clean Up Process Complete')
        except Exception, e:
            self.logger.exception(e)

    def _get_hostname(self):
        #gets the hostname and stores hostname/domainname so they can be filtered out later

        try:
            hostfile = os.path.join(self.dir_path, 'hostname')
            fh = open(hostfile, 'r')
            name_list = fh.readline().rstrip().split('.')
            is_fqdn = True

            if len(name_list) == 1: #if it's not an FQDN - no dots
                is_fqdn = False

            hostname = name_list[0]
            if is_fqdn:
                domainname = '.'.join(name_list[1:len(name_list)])
            else:
                domainname = 'not-an-fqdn'

            return hostname, domainname, is_fqdn

        except Exception, e:
            self.logger.exception(e)
            raise Exception('GetHostname Error: Cannot resolve hostname from %s') % hostfile

    def _ip2int(self, ipstr):
        #converts a dotted decimal IP address into an integer that can be incremented
        integer = struct.unpack('!I', socket.inet_aton(ipstr))[0]

        return integer

    def _int2ip(self, num):
        #converts an integer stored in the IP database into a dotted decimal IP
        ip = socket.inet_ntoa(struct.pack('!I', num))

        return ip

    def _ip2db(self, ip):
        '''
        adds an IP address to the IP database and returns the obfuscated entry, or returns the
        existing obfuscated IP entry
        FORMAT:
        {$obfuscated_ip: $original_ip,}
        '''

        ip_num = self._ip2int(ip)
        ip_found = False
        db = self.ip_db
        for k,v in db.iteritems():
            if v == ip_num:
                ret_ip = self._int2ip(k)
                ip_found = True
        if ip_found:                #the entry already existed
            return ret_ip
        else:                       #the entry did not already exist
            if len(self.ip_db) > 0:
                new_ip = max(db.keys()) + 1
            else:
                new_ip = self._ip2int(self.start_ip)
            db[new_ip] = ip_num

            return self._int2ip(new_ip)

    def _hn2db(self, hn):
        '''
        This will add a hostname for an FQDN on the same domain as the host to an obfuscation database,
        or return an existing entry
        '''
        db = self.hn_db
        hn_found = False
        for k,v in db.iteritems():
            if v == hn:  #the hostname is in the database
                ret_hn = k
                hn_found = True
        if hn_found:
            return ret_hn
        else:
            self.hostname_count += 1    #we have a new hostname, so we increment the counter to get the host ID number
            if self.is_fqdn:    #it's an fqdn, so we add in the obfuscated domainname
                new_hn = "host%s.%s" % (self.hostname_count, self.domain)
            else:
                new_hn = "host%s" % self.hostname_count
            self.hn_db[new_hn] = hn

            return new_hn

    def _walk_report(self, folder):
        '''returns a dictonary of dictionaries in the format {directory_name:[file1,file2,filex]}'''

        dir_list = {}
        try:
            for dirName, subdirList, fileList in os.walk(folder):
                x = []
                for fname in fileList:
                    x.append(fname)
                dir_list[dirName] = x

            return dir_list
        except Exception, e:
            self.logger.exception(e)
            raise Exception("WalkReport Error: Unable to Walk Report")

    def _file_list(self, folder):
        '''returns a list of file names in an sosreport directory'''
        rtn = []
        walk = self._walk_report(folder)
        for key,val in walk.items():
            for v in val:
                x=os.path.join(key,v)
                rtn.append(x)

        self.file_count = len(rtn)  #a count of the files we'll have in the final cleaned sosreport, for reporting
        return rtn

    def _clean_line(self, l):
        '''this will return a line with obfuscations for all possible variables, hostname, ip, etc.'''

        new_line = self._sub_ip(l)  #IP substitution
        new_line = self._sub_hostname(new_line)    #Hostname substitution

        return new_line

    def _clean_file(self, f):
        '''this will take a given file path, scrub it accordingly, and save a new copy of the file
        in the same location'''
        if os.path.exists(f) and not os.path.islink(f):
            tmp_file = tempfile.TemporaryFile()
            try:
                fh = open(f,'r')
                data = fh.readlines()
                fh.close()
                if len(data) > 0: #if the file isn't empty:
                    for l in data:
                        new_l = self._clean_line(l)
                        tmp_file.write(new_l)

                    tmp_file.seek(0)

            except Exception, e:
                self.logger.exception(e)
                raise Exception("CleanFile Error: Cannot Open File For Reading - %s" % f)

            try:
                if len(data) > 0:
                    new_fh = open(f, 'w')
                    for line in tmp_file:
                        new_fh.write(line)
                    new_fh.close()
            except Exception, e:
                self.logger.exception(e)
                raise Exception("CleanFile Error: Cannot Write to New File - %s" % f)

            finally:
                tmp_file.close()

    def clean_report(self):
        '''this will loop through all the files in a dir_pathectory and scrub them'''

        files = self._file_list(self.dir_path)
        if not self.is_fqdn:
            self.logger.con_out("The Hostname Does Not Appear to be an FQDN - Limited Cleaning Available")
        self.logger.con_out("SOSCleaner Started")
        self.logger.con_out("Working Directory - %s", self.dir_path)
        self.logger.con_out("IP Substitution Start Address - %s", self.start_ip)
        self.logger.con_out("Domain Name Substitution - %s", self.domain)
        for f in files:
            self.logger.debug("Cleaning %s", f)
            self._clean_file(f)
        self.logger.con_out("SOSCleaner Completed")
        self.logger.con_out("IP Addresses Obfuscated - %s", len(self.ip_db))
        self.logger.con_out("Hostnames Obfuscated - %s" , len(self.hn_db))
        self.logger.con_out("Files Cleaned - %s", self.file_count)
        if self.reporting:
            self._create_reports()
        self._create_archive()

        return_data = (self.archive_path, self.logfile, self.ip_report, self.hn_report)

        return return_data
