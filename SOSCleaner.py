#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# Copyright (C) 2013  Jamie Duncan (jamie.e.duncan@gmail.com)

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
# Last Modified : Fri 06 Dec 2013 04:35:56 PM EST
# Purpose :

import os
import re
from python_magic import magic
from time import strftime, gmtime
import shutil
import struct, socket
import tempfile
import textwrap
import logging
import tarfile

class SOSCleaner:
    '''
    A class to parse through an sosreport and begin the cleaning process required in many industries
    Parameters:
    compress - will create a gzip'd tarball of the cleaned sosreport - defaults to yes. Can disable if user wants to eyeball scan afterwards
    debug - will generate add'l output to STDOUT. defaults to no
    reporting - will post progress and overall statistics to STDOUT. defaults to yes
    xsos - instead of copying over the whole sosreport, we perform an xsos-style operation, outputting summary data instead
    '''
    def __init__(self, sosreport, compress, loglevel, reporting, xsos):

        self._check_uid()
        self.version = '0.1'
        self.compress = compress
        self.loglevel = loglevel
        self.reporting = reporting
        self.xsos = xsos
        self.ip_db = {}
        self.start_ip = '10.230.230.0'
        self.hn_db = {}
        self.hostname_count = 0
        self.domain = 'example.com'
        self.working_dir, self.logfile, self.session = self._get_workingdir()
        loglevel_config = 'logging.%s' % self.loglevel
        logging.basicConfig(filename=self.logfile, level=eval(loglevel_config), format='%(asctime)s : %(levelname)s : %(message)s')
        self.report = self._get_sosreport_path(sosreport)

        if self.reporting:
            logging.info("Reporting Will Be Enabled Soon")

        if not self.xsos:
            self._make_dest_env()   #create the working directory
            self.hostname, self.domainname, self.is_fqdn = self._get_hostname()

        else:
            raise Exception("This IS COMING SOON!")

    def _check_uid(self):
        uid = os.getuid()
        if uid != 0:
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
                    if mode == '200' or mode == '444' or mode == '400':
                        skip_list.append(f)
                    if magic.from_file(f_full) == 'data':
                        skip_list.append(f)

        return skip_list

    def _get_sosreport_path(self, path):
        '''
        This will look for common compression types and decompresses accordingly
        '''
        logging.info("Beginning SOSReport Extraction")
        compression_sig = magic.from_file(path).split(',')[0]
        if 'directory' in compression_sig:
            logging.info('%s appears to be a %s - continuing', path, compression_sig)
            return path #it's an unzipped directory, so get to copying

        elif 'compressed data' in compression_sig:
            p = tarfile.open(path, 'r')

            timestamp = strftime("%Y%m%d%H%M%S", gmtime())
            dir_path = "/tmp/soscleaner-%s" % timestamp
            logging.info('Data Source Appears To Be %s - decompressing into %s', compression_sig, dir_path)
            extract_path = '/tmp/soscleaner-origin-%s' % timestamp
            try:
                p.extractall(extract_path)
                return_path = os.path.join(extract_path, os.path.commonprefix(p.getnames()))
                self.origin_dir = extract_path

                return return_path

            except Exception, e:
                logging.exception(e)
                raise Exception("DeCompressionError: Unable to De-Compress %s into %s", path, extract_path)
        else:
            raise Exception('CompressionError: Unable To Determine Compression Type')

    def _sub_ip(self, line):
        '''
        This will substitute an obfuscated IP for each instance of a given IP in a file
        This is called in the self._clean_line function, along with user _sub_* functions to scrub a given line in a file.
        It scans a given line and if an IP exists, it obfuscates the IP using _ip2db and returns the altered line
        '''
        pattern = r"(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
        #pattern = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([ (\[]?(\.|dot)[ )\]]?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})"
        ips = [each[0] for each in re.findall(pattern, line)]
        if len(ips) > 0:
            for ip in ips:
                new_ip = self._ip2db(ip)
                logging.debug("Obfuscating IP - %s > %s", ip, new_ip)
                line = line.replace(ip, new_ip)
        return line

    def _sub_hostname(self, line):
        '''
        This will replace the exact hostname and all instances of the domain name with the obfuscated alternatives.
        Example:
        '''
        if self.is_fqdn:
            regex = re.compile(r'\w*\.%s' % self.domainname)
            hostnames = [each for each in regex.findall(line)]
            if len(hostnames) > 0:
                for hn in hostnames:
                    new_hn = self._hn2db(hn)
                    logging.debug("Obfuscating FQDN - %s > %s", hn, new_hn)
                    line = line.replace(hn, new_hn)

        '''
        logs like secure have a non-FQDN hostname entry on almost every line.
        So we will always run this bit of code to clean up as much as possibe, in addition
        to searching for all of the FQDNs that we know exist.
        we don't have an FQDN, so we will only do a 1:1 replacement for the hostname
        '''

        new_hn = self._hn2db(self.hostname)
        logging.debug("Obfuscating Non-FQDN - %s > %s", self.hostname, new_hn)
        line = line.replace(self.hostname, new_hn)

        return line

    def _get_workingdir(self):

        timestamp = strftime("%Y%m%d%H%M%S", gmtime())
        dir_path = "/tmp/soscleaner-%s" % timestamp
        session = "soscleaner-%s" % timestamp
        logfile = "/tmp/%s.log" % session

        return dir_path, logfile, session

    def _make_dest_env(self):
        '''
        This will create the folder in /tmp to store the sanitized files and populate it using shutil
        These are the files that will be scrubbed
        '''
        dir_path = self.working_dir

        try:
            shutil.copytree(self.report, dir_path, symlinks=True, ignore=self._skip_file)
        except Exception, e:
            logging.exception(e)
            raise Exception("DestinationEnvironment Error: Cannot Create Destination Environment")

    def _create_archive(self):
        '''This will create a tar.gz compressed archive of the scrubbed directory'''
        archive = "/tmp/%s.tar.gz" % self.session
        logging.info('Starting Archiving Process - Creating %s', archive)
        t = tarfile.open(archive, 'w:gz')
        for dirpath, dirnames, filenames in os.walk(self.working_dir):
            for f in filenames:
                f = os.path.join(dirpath,f)
                logging.debug('adding %s to %s archive', f, archive)
                t.add(f)
        self._clean_up()
        logging.info('Archiving Complete')
        logging.info('SOSCleaner Complete')
        t.add(self.logfile)
        t.close()

    def _clean_up(self):
        '''This will clean up origin directories, etc.'''
        logging.info('Beginning Clean Up Process')
        try:
            if self.origin_dir:
                logging.info('Removing Origin Directory - %s', self.origin_dir)
                shutil.rmtree(self.origin_dir)
            logging.info('Compression Enabled - Removing Working Directory - %s', self.working_dir)
            shutil.rmtree(self.working_dir)
            logging.info('Clean Up Process Complete')
        except Exception, e:
            logging.exception(e)

    def _get_hostname(self):
        #gets the hostname and stores hostname/domainname so they can be filtered out later

        try:
            hostfile = os.path.join(self.working_dir, 'hostname')
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
            logging.exception(e)
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
        adds an IP address to the IP database and returns the obfuscated entry, or returns the existing obfuscated IP entry
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
        This will add a hostname for an FQDN on the same domain as the host to an obfuscation database, or return an existing entry
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
            logging.exception(e)
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
        '''this will take a given file path, scrub it accordingly, and save a new copy of the file in the same location'''
        if os.path.exists(f) and not os.path.islink(f):
            mode = oct(os.stat(f).st_mode)[-3:]
            if mode == '555' or mode == '500':
                os.system('chmod 777 %s' % f)
            if mode == '232':
                os.system('chmod 666 %s' % f)
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
                logging.exception(e)
                raise Exception("CleanFile Error: Cannot Open File For Reading - %s" % f)

            try:
                if len(data) > 0:
                    new_fh = open(f, 'w')
                    for line in tmp_file:
                        new_fh.write(line)
                    new_fh.close()
            except Exception, e:
                logging.exception(e)
                raise Exception("CleanFile Error: Cannot Write to New File - %s" % f)

            finally:
                tmp_file.close()

    def clean_report(self):
        '''this will loop through all the files in a working_directory and scrub them'''

        files = self._file_list(self.working_dir)
        if not self.is_fqdn:
            logging.warning("The Hostname Does Not Appear to be an FQDN - Limited Cleaning Available")
        logging.info("SOSCleaner Started")
        logging.info("Working Directory - %s", self.working_dir)
        print "Working Directory - %s" % self.working_dir
        logging.info("IP Substitution Start Address - %s", self.start_ip)
        logging.info("Domain Name Substitution - %s", self.domain)
        for f in files:
            logging.debug("Cleaning %s", f)
            self._clean_file(f)
        logging.info("SOSCleaner Completed")
        logging.info("IP Addresses Obfuscated - %s", len(self.ip_db))
        logging.info("Hostnames Obfuscated - %s" , len(self.hn_db))
        logging.info("Files Cleaned - %s", self.file_count)
        if self.compress:
            self._create_archive()
        else:
            logging.info("Compression Not Enabled - No Archive Created")
            logging.info("SOSCleaner Complete")
