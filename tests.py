#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# Copyright (C) 2014  Jamie Duncan (jamie.e.duncan@gmail.com)

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

# File Name : test.py
# Creation Date : 07-02-2014
# Created By : Jamie Duncan
# Last Modified : Sat 13 Sep 2014 10:55:29 PM EDT
# Purpose : SOSCleaner unittests
import sys
sys.path.append('src/')
import unittest
from soscleaner import SOSCleaner
import os
import shutil

class SOSCleanerTests(unittest.TestCase):

    def _setUpHostname(self, t='fqdn', remove=False):

        hostname_f = os.path.join(self.testdir, 'hostname')
        if remove:
            os.remove(hostname_f)
            return True

        fh = open(hostname_f, 'w')
        if t == 'non-fqdn':
            fh.write('myhost\n')
        else:
            fh.write('myhost.myserver.com\n')

        fh.close()

    def _setUpHostnamePath(self, t='fqdn', remove=False):

        hostname_f = os.path.join(self.testdir, 'hostname2')
        if remove:
            os.remove(hostname_f)
            return True

        fh = open(hostname_f, 'w')
        if t == 'non-fqdn':
            fh.write('myhost2\n')
        else:
            fh.write('myhost2.myserver2.com\n')

        fh.close()

    def setUp(self):
        print "\nSOSCleanerTest:setUp_:begin"
        self.testdir = 'testdata/sosreport_dir'
        self.cleaner = SOSCleaner(quiet=True)
        self.cleaner.origin_path, self.cleaner.dir_path, self.cleaner.session, self.cleaner.logfile, self.cleaner.uuid = self.cleaner._prep_environment()
        self.cleaner._start_logging(self.cleaner.logfile)
        print "SOSCleanerTest:setUp_:end"

    def _artifact_cleanup(self,directory):
        #clean up the /tmp directory between tests, when artifacts are created
        for f in os.listdir(directory):
            a = os.path.join(directory,f)
            if 'soscleaner' in f:
                if os.path.isdir(a):
                    print "Removing Directory: %s" % a
                    shutil.rmtree(a)
                else:
                    print "Removing File: %s" % a
                    os.remove(a)

    def tearDown(self):
        print "SOSCleanerTest:tearDown_:begin"
        #self._artifact_cleanup('/tmp')
        print "SOSCleanerTest:tearDown_:end"

    def test_prep_environment(self):
        # _prep_environment() should create 4 values
        # * self.origin_path - path the sosreport is extracted to
        # * self.dir_path - path cleaned report is written to
        # * self.session - soscleaner-$timestamp - used for naming files/reports/etc.
        # * self.logfile - location of logfile

        print "SOSCleanerTest:test_prep_environment:begin"
        self.assertTrue('soscleaner-origin' in self.cleaner.origin_path)
        self.assertTrue('soscleaner' in self.cleaner.dir_path)
        self.assertTrue('soscleaner' in self.cleaner.session)
        self.assertTrue('log' in self.cleaner.logfile)
        print "SOSCleanerTest:test_prep_environment:end"

    def test_sub_ip_new(self):
        # _sub_ip() should substitute a new IP into the IP database
        print "SOSCleanerTest:test_sub_ip_new:begin"
        line = 'test test2 192.168.1.1 test3'
        new_line = self.cleaner._sub_ip(line)
        self.assertFalse(line == new_line)
        print "SOSCleanerTest:test_sub_ip_new:end"

    def test_sub_ip_existing(self):
        # _sub_ip() should retrieve an existing IP from the database

        print "SOSCleanerTest:test_sub_ip_existing:begin"
        line = 'test test2 192.168.1.2 test3'
        new_line = self.cleaner._sub_ip(line)
        newer_line = self.cleaner._sub_ip(line)
        self.assertTrue(new_line == newer_line)
        print "SOSCleanerTest:test_sub_ip_existing:end"

    def test_get_hostname_fqdn(self):
        # _get_hostname should return the hostname and domainname from the sosreport. testing with an fqdn
        print "SOSCleanerTest:test_get_hostname_fqdn:begin"
        self.cleaner.dir_path = 'testdata/sosreport_dir'
        self._setUpHostname(t='fqdn')
        host, domain = self.cleaner._get_hostname()
        self.assertTrue(host == 'myhost')
        self.assertTrue(domain == 'myserver.com')
        print "SOSCleanerTest:test_get_hostname_fqdn:end"

    def test_get_hostname_nonfqdn(self):
        # testing with a non-fqdn
        print "SOSCleanerTest:test_get_hostname_nonfqdn:begin"
        self.cleaner.dir_path = 'testdata/sosreport_dir'
        self._setUpHostname(t='non-fqdn')
        host, domain = self.cleaner._get_hostname()
        self.assertTrue(host == 'myhost')
        self.assertTrue(domain == None)
        print "SOSCleanerTest:test_get_hostname_nonfqdn:end"

    def test_get_hostname_nohostnamefile(self):
        # testing with no hostname file
        print "SOSCleanerTest:test_get_hostname_nohostnamefile:begin"
        self.cleaner.dir_path = 'testdata/sosreport_dir'
        self._setUpHostname(remove=True)
        host,domain = self.cleaner._get_hostname()
        self.assertTrue(host == None)
        self.assertTrue(domain == None)

    def test_get_hostname_path_fqdn(self):
        # _get_hostname should return the hostname and domainname from the sosreport. testing with an fqdn
        print "SOSCleanerTest:test_get_hostname_fqdn:begin"
        self.cleaner.dir_path = 'testdata/sosreport_dir'
        self._setUpHostnamePath(t='fqdn')
        host, domain = self.cleaner._get_hostname('hostname2')
        self.assertTrue(host == 'myhost2')
        self.assertTrue(domain == 'myserver2.com')
        print "SOSCleanerTest:test_get_hostname_fqdn:end"

    def test_get_hostname_path_nonfqdn(self):
        # testing with a non-fqdn
        print "SOSCleanerTest:test_get_hostname_nonfqdn:begin"
        self.cleaner.dir_path = 'testdata/sosreport_dir'
        self._setUpHostnamePath(t='non-fqdn')
        host, domain = self.cleaner._get_hostname('hostname2')
        self.assertTrue(host == 'myhost2')
        self.assertTrue(domain == None)
        print "SOSCleanerTest:test_get_hostname_nonfqdn:end"

    def test_get_hostname_path_nohostnamefile(self):
        # testing with no hostname file
        print "SOSCleanerTest:test_get_hostname_nohostnamefile:begin"
        self.cleaner.dir_path = 'testdata/sosreport_dir'
        self._setUpHostnamePath(remove=True)
        host,domain = self.cleaner._get_hostname('hostname2')
        self.assertTrue(host == None)
        self.assertTrue(domain == None)

    def test_obfuscate_hosts_file(self):
        # testing hosts file extra processing
        print "SOSCleanerTest:test_obfuscate_hosts_file:begin"
        self.cleaner.dir_path = 'testdata/sosreport_dir'
        self.cleaner._process_hosts_file()
        self.assertTrue('myhost' in self.cleaner.hn_db.values())
        print "SOSCleanerTest:test_obfuscate_hosts_file:end"

    def test_ip2int(self):
        print "SOSCleanerTest:test_ip2int:begin"
        num = self.cleaner._ip2int('192.168.1.10')
        self.assertTrue(num == 3232235786)
        print "SOSCleanerTest:test_ip2int:end"

    def test_int2ip(self):
        print "SOSCleanerTest:test_int2ip:begin"
        ip = self.cleaner._int2ip(3232235786)
        self.assertTrue(ip == '192.168.1.10')
        print "SOSCleanerTest:test_int2ip:end"

    def test_ip2db_newip(self):
        print "SOSCleanerTest:test_ip2db_newip:begin"
        self.cleaner.ip_db = dict()  #initialize a new IP database to be sure
        test_ip = '192.168.1.10'
        test_int = self.cleaner._ip2int(test_ip)
        self.cleaner._ip2db(test_ip)
        self.assertTrue(test_int in self.cleaner.ip_db.values())
        print "SOSCleanerTest:test_int2ip_newip:end"

    def test_ip2db_addlip(self):
        print "SOSCleanerTest:test_ip2db_addlip:begin"
        self.cleaner.ip_db = dict() #initialize a new IP database to be sure
        test_ip1 = '192.168.1.10'
        test_ip2 = '192.168.1.11'
        test_int2 = self.cleaner._ip2int(test_ip2)
        self.cleaner._ip2db(test_ip1)
        self.cleaner._ip2db(test_ip2)
        self.assertTrue(test_int2 in self.cleaner.ip_db.values())
        print "SOSCLeanerTest:test_ip2db_addlip:end"

    def test_ip2db_existingip(self):
        print "SOSCleanerTest:test_ip2db_existingip:begin"
        self.cleaner.ip_db = dict()
        orig_ob_ip = self.cleaner._ip2db('192.168.1.10')
        test_ip = '192.168.1.10'
        new_ob_ip = self.cleaner._ip2db(test_ip)
        self.assertTrue(new_ob_ip == orig_ob_ip)
        self.assertTrue(len(self.cleaner.ip_db) == 1)
        print "SOSCleanerTest:test_ip2db_existingip:end"

    def test_skip_files(self):
        print "SOSCleanerTest:test_skip_files:begin"
        d = 'testdata/sosreport_dir'
        files = ['test.bin','test.txt']
        skip_list = self.cleaner._skip_file(d,files)
        self.assertTrue('test.bin' in skip_list)
        self.assertTrue('test.txt' not in skip_list)
        print "SOSCleanerTest:test_skip_files:end"

    def test_extract_sosreport_dir(self):
        print "SOSCleaner:test_extract_sosreport_dir:begin"
        d = self.cleaner._extract_sosreport(self.testdir)
        self.assertTrue(d == self.testdir)
        print "SOSCleaner:test_extract_sosreport_dir:end"

    def test_extract_sosreport_gz(self):
        print "SOSCleaner:test_extract_sosreport_gz:begin"
        d = self.cleaner._extract_sosreport('testdata/sosreport1.tar.gz')
        check_d = '/tmp/soscleaner-origin-%s/sosreport_dir' % self.cleaner.uuid
        self.assertTrue(d == check_d)
        print "SOSCleaner:test_extract_sosreport_gz:end"

    def test_extract_sosreport_bz(self):
        print "SOSCleaner:test_extract_sosreport_bz:begin"
        d = self.cleaner._extract_sosreport('testdata/sosreport1.tar.gz')
        check_d = '/tmp/soscleaner-origin-%s/sosreport_dir' % self.cleaner.uuid
        self.assertTrue(d == check_d)
        print "SOSCleaner:test_extract_sosreport_bz:end"

    def test_extract_sosreport_xz(self):
        print "SOSCleaner:test_extract_sosreport_xz:begin"
        d = self.cleaner._extract_sosreport('testdata/sosreport1.tar.xz')
        check_d = '/tmp/soscleaner-origin-%s/sosreport_dir' % self.cleaner.uuid
        self.assertTrue(d == check_d)
        print "SOSCleaner:test_extract_sosreport_xz:end"

    def test_clean_line(self):
        print "SOSCleanerTest:test_clean_line:begin"
        hostname = 'myhost.myservers.com'
        ip = '192.168.1.10'
        line = "foo bar %s some words %s more words" % (hostname, ip)
        self.cleaner.hostname = hostname
        self.cleaner.process_hostnames = True
        self.cleaner.domainname = 'example.com'
        self.cleaner.dn_db['example.com'] = 'myservers.com'
        new_line = 'foo bar %s some words %s more words' % (self.cleaner._hn2db(hostname), self.cleaner._ip2db(ip))
        self.assertTrue(self.cleaner._clean_line(line) == new_line)
        print "SOSCleanerTest:test_clean_line:end"

    def test_make_dest_env(self):
        print "SOSCleanerTest:test_make_dest_env:begin"
        self.cleaner.report = self.testdir
        self.cleaner._make_dest_env()
        self.assertTrue(os.path.isdir(self.cleaner.dir_path))
        print "SOSCleanerTest:test_make_dest_env:begin"

    def test_create_archive(self):
        print "SOSCleanerTest:test_create_archive:begin"
        origin_test = '/tmp/origin-testdir'
        dir_test = '/tmp/path-testdir'
        for d in origin_test, dir_test:
            if not os.path.exists(d):
                shutil.copytree(self.testdir, d)
        self.cleaner.origin_path = origin_test
        self.cleaner.dir_path = dir_test
        print self.cleaner.logfile
        print os.path.isfile(self.cleaner.logfile)
        self.cleaner._create_archive()
        self.assertTrue(os.path.isfile(self.cleaner.archive_path))
        self.assertFalse(os.path.exists(origin_test))
        self.assertFalse(os.path.exists(dir_test))
        print "SOSCleanerTest:test_create_archive:end"

    def test_domains2db_fqdn(self):
        print "SOSCleanerTest:test_domains2db_fqdn:begin"
        self.cleaner.domainname = 'myserver.com'
        self.cleaner.domains = ['foo.com','bar.com']
        self.cleaner._domains2db()
        self.assertTrue(self.cleaner.domainname in self.cleaner.dn_db.values())
        self.assertTrue('foo.com' in self.cleaner.dn_db.values())
        self.assertTrue('bar.com' in self.cleaner.dn_db.values())
        print "SOSCleanerTest:test_domains2db_fqdn:end"

    def test_file_list(self):
        print "SOSCleanerTest:test_file_list:begin"
        x = self.cleaner._file_list('testdata/sosreport_dir')
        self.assertTrue('testdata/sosreport_dir/var/log/messages' in x)
        self.assertTrue('testdata/sosreport_dir/hostname' in x)
        print "SOSCleanerTest:test_file_list:end"

    def test_create_ip_report(self):
        print "SOSCleanerTest:test_create_ip_report:begin"
        test_ip = '192.168.1.10'
        test_o_ip = self.cleaner._ip2db(test_ip)
        self.cleaner._create_ip_report()
        fh = open(self.cleaner.ip_report,'r')
        x = fh.readlines()
        self.assertTrue(test_ip in x[1])
        self.assertTrue(test_o_ip in x[1])
        print "SOSCleanerTest:test_create_ip_report:end"

    def test_create_hn_report(self):
        print "SOSCleanerTest:test_create_hn_report:begin"
        test_hn = 'myhost.myserver.com'
        self.cleaner.domainname = 'myserver.com'
        self.cleaner.process_hostnames = True
        test_o_hn = self.cleaner._hn2db(test_hn)
        self.cleaner._create_hn_report()
        fh = open(self.cleaner.hn_report,'r')
        x = fh.readlines()
        self.assertTrue(test_hn in x[1])
        self.assertTrue(test_o_hn in x[1])
        print "SOSCleanerTest:test_create_hn_report:end"

    def test_create_hn_report_nohn(self):
        print "SOSCleanerTest:test_create_hn_report_nohn:begin"
        self.cleaner.process_hostnames = False
        self.cleaner._create_hn_report()
        fh = open(self.cleaner.hn_report, 'r')
        lines = fh.readlines()
        self.assertTrue(lines[1] == 'None,None\n')
        print "SOSCleanerTest:test_create_hn_report_nohn:end"

    def test_create_dn_report(self):
        print "SOSCleanerTest:test_create_dn_report:begin"
        self.cleaner.domainname = 'myserver.com'
        self.cleaner.domains = ['myserver.com']
        self.cleaner._domains2db()
        self.cleaner._create_dn_report()
        fh = open(self.cleaner.dn_report,'r')
        x = fh.readlines()
        self.assertTrue( self.cleaner.domainname in x[1])
        print "SOSCleanerTest:test_create_dn_report:end"

    def test_create_dn_report_none(self):
        print "SOSCleanerTest:test_create_dn_report_none:begin"
        self.cleaner._create_dn_report()
        fh = open(self.cleaner.dn_report,'r')
        x = fh.readlines()
        self.assertTrue( x[1] == 'None,None\n')
        print "SOSCleanerTest:test_create_dn_report_none:end"

    def test_clean_file(self):
        print "SOSCleanerTest:test_clean_file:begin"
        test_file = '/tmp/clean_file_test'
        shutil.copyfile('testdata/sosreport_dir/var/log/messages', test_file)
        self.cleaner.process_hostnames = True
        self.cleaner.domains = ['myserver.com','foo.com']
        self.cleaner.domainname = 'myserver.com'
        self.cleaner.hostname = 'myhost'
        self.cleaner._domains2db()
        self.cleaner._clean_file(test_file)
        fh = open(test_file,'r')
        data = ', '.join(fh.readlines())
        fh.close()
        self.assertTrue(self.cleaner._hn2db(self.cleaner.hostname) in data)
        self.assertTrue(self.cleaner._hn2db('foohost.foo.com') in data)
        os.remove(test_file)    #clean up
        print "SOSCleanerTest:test_clean_file:end"

    def test_sub_hostname_hyphens(self):
        print "SOSCleanerTest:test_sub_hostname_hyphens:begin"
        self.cleaner.domains=['myserver.com']
        self.cleaner.domainname='myserver.com'
        self.cleaner.hostname='myhost'
        self.cleaner._domains2db()
        line = 'this is myhost.myserver.com and this is my-host.myserver.com'
        new_line = self.cleaner._sub_hostname(line)
        self.assertTrue('my' not in new_line)
        print "SOSCleanerTest:test_sub_hostname_hyphens:end"

    def test_extra_files(self):
        print "SOSCleanerTest:test_extra_files:begin"
        files = ['testdata/extrafile1','testdata/extrafile2','testdata/extrafile3']
        self.cleaner._clean_files_only(files)
        self.assertTrue(os.path.isdir(self.cleaner.dir_path))
        self.assertTrue(os.path.exists(os.path.join(self.cleaner.dir_path, 'extrafile3')))
        print "SOSCleanerTest:test_extra_files:end"

    def test_create_archive_nososreport(self):
        print "SOSCleanerTest:test_create_archive_nososreport:begin"
        files = ['testdata/extrafile1','testdata/extrafile2','testdata/extrafile3']
        self.cleaner._clean_files_only(files)
        self.assertTrue(os.path.exists(os.path.join(self.cleaner.dir_path, 'extrafile3')))
        print "SOSCleanerTest:test_create_archive_nososreport:end"

    def test_extra_files_nonexistent(self):
        print "SOSCleanerTest:test_extra_files_nonexistent:begin"
        files = ['testdata/extrafile1','testdata/extrafile2','testdata/extrafile3', 'testdata/bogusfile']
        self.cleaner._clean_files_only(files)
        self.assertTrue(os.path.exists(os.path.join(self.cleaner.dir_path, 'extrafile3')))
        self.assertFalse(os.path.exists(os.path.join(self.cleaner.dir_path, 'bogusfile')))
        print "SOSCleanerTest:test_extra_files_nonexistent:end"

    def test_clean_files_only_originexists(self):
        print "SOSCleanerTest:test_clean_files_only_originexists:begin"
        os.makedirs(self.cleaner.origin_path)
        files = ['testdata/extrafile1','testdata/extrafile2','testdata/extrafile3', 'testdata/bogusfile']
        self.cleaner._clean_files_only(files)
        self.assertTrue(os.path.exists(self.cleaner.origin_path))
        print "SOSCleanerTest:test_clean_files_only_originexists:end"

    def test_add_keywords_badfile(self):
        print "SOSCleanerTest:test_add_keywords_badfile:begin"
        self.cleaner.keywords = ['testdata/keyword_bad.txt']
        self.cleaner._keywords2db()
        self.assertTrue(self.cleaner.kw_count == 0)
        print "SOSCleanerTest:test_add_keywords_badfile:end"

    def test_add_keywords(self):
        print "SOSCleanerTest:test_add_keywords:begin"
        self.cleaner.keywords = ['testdata/keyword1.txt','testdata/keyword2.txt']
        self.cleaner._keywords2db()
        self.assertTrue(self.cleaner.kw_count == 8)
        self.assertTrue(all(['foo' in self.cleaner.kw_db.keys(),'some' in self.cleaner.kw_db.keys()]))
        print "SOSCleanerTest:test_add_keywords:end"

    def test_sub_keywords(self):
        print "SOSCleanerTest:test_sub_keywords:begin"
        self.cleaner.keywords = ['testdata/keyword1.txt']
        self.cleaner._keywords2db()
        test_line = 'this is a sample foo bar. this should be different bar foo.'
        new_line = self.cleaner._sub_keywords(test_line)
        self.assertTrue(all(['keyword0' in new_line, 'keyword1' in new_line]))
        print "SOSCleanerTest:test_sub_keywords:end"

if __name__ == '__main__':
    unittest.main()
