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
# Last Modified : Tue 26 Nov 2013 12:48:15 PM EST
# Purpose :

import os
import re
from python_magic import magic
from time import strftime, gmtime
import shutil
import struct, socket
import tempfile

class SOSCleaner:
    '''a class to parse through an sosreport and begin the cleaning process required in many industries'''

    def __init__(self, sosreport, compress=True, debug=False):

        self.version = '0.1'
        self.report = sosreport
        self.compress = compress    # whether or not to tar up the sanitized output. defaults to yes
        self.debug = debug          # prints some stuff to stdout
        self.r_ip = "(.*[\/\s:;\a]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*)"
        self.ip_db = {} #stored in Obfuscated:Original pairings
        self.start_ip = '10.230.230.0'
        self.exceptions = ('proc/sys/net/.*/route/flush',)  #a list of regex parameters to bypass

        self._make_dest_env()   #create the working directory

    def _skip_file(self, d, files):
        '''the function passed into shutil.copytree to ignore certain patterns and filetypes'''
        skip_list = []
        for f in files:
            f_full = os.path.join(d, f)
            if not os.path.isdir(f_full):
                if not os.path.islink(f_full):
                    mode = oct(os.stat(f_full).st_mode)[-3:]
                    if mode == '200':
                        skip_list.append(f) #don't copy write-only devices
                    if magic.from_file(f_full) == 'data':
                        skip_list.append(f)

        return skip_list

    def _swap_ip(self, match):
        '''used to pass into re.sub to alter the IP address'''

        rtn = ''
        s_match = match.split()
        rtn = match
        for b in range(0, len(s_match) -1):
            if self.debug:
                print "TESTING: %s" % s_match[b]
                if '127.0.0.1' not in s_match[b]:
                    m = re.search('.*[\/\s\W:;\a](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*', s_match[b])
                    if m:
                        s_match[b] = self._ip2db(s_match[b])
        rtn = ' '.join(map(str, s_match))

        return rtn

    def _make_dest_env(self):
        '''this will create the folder in /tmp to store the sanitized files and populate it with the scrubbed files using shutil'''

        timestamp = strftime("%Y%m%d%H%M%S", gmtime())
        dir_path = "/tmp/soscleaner-%s" % timestamp

        shutil.copytree(self.report, dir_path, symlinks=True, ignore=self._skip_file)
        self.working_dir = dir_path

    def _tar_results(self, dir_path):
        '''tars and compresses a directory full of sanitized stuff'''
        output_file = "%s.tar.gz" % dir_path
        with tarfile.open(output_file, "w:gz") as tar:
            tar.add(dir_path, arcname=os.path.basename(dir_path))

        return tar

    def _ip2int(self, ipstr):
        '''converts a dotted decimal IP address into an integer that can be incremented'''
        integer = struct.unpack('!I', socket.inet_aton(ipstr))[0]

        return integer

    def _int2ip(self, num):
        '''converts an integer stored in the IP database into a dotted decimal IP'''
        ip = socket.inet_ntoa(struct.pack('!I', num))

        return ip

    def _ip2db(self, ip):
        '''adds an IP address to the IP database and returns the obfuscated entry, or returns the existing obfuscated IP entry
        FORMAT:
        {$obfuscated_ip: $original_ip,}'''

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
        for dirName, subdirList, fileList in os.walk(folder):
            x = []
            for fname in fileList:
                x.append(fname)
            dir_list[dirName] = x

        return dir_list

    def _file_list(self, folder):
        '''returns a list of file names in an sosreport directory'''
        rtn = []
        walk = self._walk_report(folder)
        for key,val in walk.items():
            for v in val:
                x=os.path.join(key,v)
                rtn.append(x)

        return rtn

    def _string_search(self, regex):
        '''takes a list of files and searches through them all for a given regex pattern'''
        try:
            files = self._file_list(self.working_dir)
        except:
            raise Exception('no working directory defined')

        for fpath in files:
            if os.path.isfile(fpath):
                os.system("chmod 664 %s" % fpath) #a kludge, I know...
                if self.debug:
                    print "PROCESSING: %s" % fpath
                f = open(fpath, 'r+')
                lines = f.readlines()
                f.seek(0)
                f.truncate()
                for l in lines:
                    ip_match = re.search(r'%s' % regex, l)
                    if ip_match:
                        l = self._swap_ip(l)
                        if self.debug:
                            print l
                    f.write(l) #write it back into the file
                f.close()
