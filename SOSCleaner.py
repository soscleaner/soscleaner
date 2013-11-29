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
# Last Modified : Fri 29 Nov 2013 12:19:33 PM EST
# Purpose :

import os
import re
from python_magic import magic
from time import strftime, gmtime
import shutil
import struct, socket
import tempfile
import textwrap

class SOSCleaner:
    '''
    A class to parse through an sosreport and begin the cleaning process required in many industries
    Parameters:
    compress - will create a gzip'd tarball of the cleaned sosreport - defaults to yes. Can disable if user wants to eyeball scan afterwards
    debug - will generate add'l output to STDOUT. defaults to no
    reporting - will post progress and overall statistics to STDOUT. defaults to yes
    '''
    def __init__(self, sosreport, compress=True, debug=False, reporting=True):

        self.version = '0.1'
        self.report = sosreport
        self.compress = compress
        self.debug = debug
        self.ip_db = {}
        self.start_ip = '10.230.230.0'
        self.hn_db = {}
        self.domain = 'example.com'
        self.reporting = reporting

        self._make_dest_env()   #create the working directory

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
                    if mode == '200':
                        skip_list.append(f)
                    if magic.from_file(f_full) == 'data':
                        skip_list.append(f)

        return skip_list

    def _sub_ip(self, line):
        '''
        This will substitute an obfuscated IP for each instance of a given IP in a file
        This is called in the self._clean_line function, along with user _sub_* functions to scrub a given line in a file.
        It scans a given line and if an IP exists, it obfuscates the IP using _ip2db and returns the altered line
        '''
        pattern = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([ (\[]?(\.|dot)[ )\]]?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})"
        ips = [each[0] for each in re.findall(pattern, line)]
        if len(ips) > 0:
            for ip in ips:
                new_ip = self._ip2db(ip)
                if self.debug:
                    print "Obfuscating IP: %s --> %s" % (ip, new_ip)
                line = line.replace(ip, new_ip)
        return line

    def _make_dest_env(self):
        '''
        This will create the folder in /tmp to store the sanitized files and populate it using shutil
        These are the files that will be scrubbed
        '''

        timestamp = strftime("%Y%m%d%H%M%S", gmtime())
        dir_path = "/tmp/soscleaner-%s" % timestamp

        try:
            shutil.copytree(self.report, dir_path, symlinks=True, ignore=self._skip_file)
            self.working_dir = dir_path
        except:
            raise Exception("DestinationEnvironment Error: Cannot Create Destination Environment")

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
        except:
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
        #
        #TODO - more cleanups
        #

        return new_line

    def _clean_file(self, f):
        '''this will take a given file path, scrub it accordingly, and save a new copy of the file in the same location'''
        if os.path.exists(f):
            tmp_file = tempfile.TemporaryFile()
            try:
                fh = open(f,'r')
                data = fh.readlines()
                fh.close()

                for l in data:
                    new_l = self._clean_line(l)
                    tmp_file.write(new_l)
                    tmp_file.seek(0)
            except:
                raise Exception("CleanFile Error: Cannot Open File For Reading")

            try:
                new_fh = open(f, 'w')
                for line in tmp_file:
                    new_fh.write(line)
                new_fh.close()
            except:
                raise Exception("CleanFile Error: Cannot Write to New File")

            finally:
                tmp_file.close()

    def clean_report(self):
        '''this will loop through all the files in a working_directory and scrub them'''

        files = self._file_list(self.working_dir)
        if self.reporting:
            print textwrap.dedent("""
            SOSCleaner Started: %s
            Working Directory: %s
            IP Substitution Address Start: %s
            Domain Name Substitution: %s
            """) % (strftime("%H:%M:%S"), self.working_dir, self.start_ip, self.domain)

        for f in files:
            if self.debug:
                print "Cleaning %s" % f
            self._clean_file(f)
        if self.reporting:
            print textwrap.dedent("""
            SOSCleaner Completed: %s
            IP Addresses Obfuscated: %s
            Hostnames Obfuscated: %s
            Files Processed: %s
            """) % (strftime("%H:%M:%S"), len(self.ip_db),len(self.hn_db), self.file_count)
        if self.compress:
            #create tarball
            if self.reporting:
                print "GZip'd Tarball Created at: %s" % 'foo'
        else:
            if self.reporting:
                print "Compression Not Enabled - No Archive Created"
