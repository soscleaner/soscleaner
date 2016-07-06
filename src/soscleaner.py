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
# Last Modified : Sat 13 Sep 2014 10:51:54 PM EDT
# Purpose : an sosreport scrubber

import os
import re
import errno
import sys
import magic
import uuid
import shutil
import struct, socket
import tempfile
import logging
import tarfile
import socket
from ipaddr import IPv4Network, IPv4Address, IPv6Network, IPv6Address

class SOSCleaner:
    '''
    A class to parse through an sosreport and begin the cleaning process required in many industries
    Parameters:
    debug - will generate add'l output to STDOUT. defaults to no
    reporting - will post progress and overall statistics to STDOUT. defaults to yes
    '''
    def __init__(self, quiet=False):

        self.name = 'soscleaner'
        self.loglevel = 'INFO' #this can be overridden by the command-line app
        self.quiet = quiet
        self.domain_count = 0
        self.domains = list()
        self.keywords = list()
        self.domainname = None
        self.report_dir = '/tmp'

        """
        Network Obfuscation Information

        Beginning with version 0.3.0, soscleaner will use the ipaddr module to manage network objects and their obfuscation
        This will let the program be much more intelligent with how it obfuscates the data while being network away, etc.

        Each entry in net_db represents a network and its obfuscated value
        net_db is a list of tuples. Each tuple has the following format:

        (original_network, obfuscated_network)
        so for each entry in net_db, x[0] is the original network as an IPv4Network object
        and x[1] is the obfuscated network as an IPv4Network object.

        Each entry in ip_db represents a found IP address and its obfuscated value

        When self.clean_report is run, it will populate net_db.
        Each time an IP is matched against, it will be compared against the values in net_db to see which network it is member to.
        The IP is then obfuscated sanely with fidelity to the subnet and relative network space.

        If an IP address is matched that doesn't exist in any other, it will be obfuscated with a 'default' Network defined as self.default_net.
        self.default_net is also used to begin incrementing for each obfuscated network

        There is also a metadata dictionary for the obfuscated networks. It tracks the number of used hosts so the obfuscated networks can be iterated cleanly.
        This is self.net_metadata. The keys are set when the networks are defined.
        Current Values:
            host_count - used to give out the next obfuscated IP address

        The length of the dictionary is also used to determine how many obfuscated networks are in use.

        Assumptions made:
        - if you use larger subnets than a /8, you will break the math for creating obfuscating networks.

          Why?
          To calculate the next obfuscation subnet, I have no idea what the next subnet mask will be, and I don't want to get into crazy CIDR calculations.
          SO
          I take the default_net's first octet, increment it by the current existing obfuscated networks, and create a subnet with the corresponding subnet mask.
          So the obfuscated network map could end up like:

          128.0.0.0/8  - default_net
          129.0.0.0/24 - an obfuscated network
          130.0.0.0/16 - network 2
          131.0.0.0/30 - network 3
          132.0.0.0/8  - network 4
          133.0.0.0/32 - network 5

          Essentially I'm burning a lot of IP addresses to keep the math simple. The default network starts 1 above the loopback, so we don't have to account for that.
          I know there are corner cases here that could break the math. I have to hope common sense will prevail... -jduncan
        """

        self.net_db = list() # Network Information database
        self.ip_db = list()
        self.default_net = IPv4Network('128.0.0.0/8')
        self.default_netmask = self.default_net.prefixlen
        self.net_count = 0  # we'll have to keep track of how many networks we have so we don't have to count them each time we need to create a new one.
        self.net_metadata = dict()

        self.net_metadata[self.default_net.network.compressed] = dict()
        self.net_metadata[self.default_net.network.compressed]['host_count'] = 0

        # Hostname obfuscation information
        self.hn_db = dict() #hostname database
        self.hostname_count = 0
        self.hostname = None

        # Domainname obfuscation information
        self.dn_db = dict() #domainname database
        self.root_domain = 'obfuscateddomain.com' #right now this needs to be a 2nd level domain, like foo.com, example.com, domain.org, etc.

        # Keyword obfuscation information
        self.keywords = None
        self.kw_db = dict() #keyword database
        self.kw_count = 0

        self.magic = magic.open(magic.MAGIC_NONE)
        self.magic.load()

    def _check_uid(self): # pragma no cover

        try:
            if os.getuid() != 0:
                self.logger.con_out("soscleaner must be executed by the root user in the same manner as sosreport")
                self.logger.con_out("soscleaner cannot continue. Exiting...")

                sys.exit(8)

        except Exception, e:    # pragma: no cover
            self.logger.exception(e)

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
                    #mode = oct(os.stat(f_full).st_mode)[-3:]
                    # executing as root makes this first if clause useless.
                    # i thought i'd already removed it. - jduncan
                    #if mode == '200' or mode == '444' or mode == '400':
                    #    skip_list.append(f)
                    if 'text' not in self.magic.file(f_full):
                        skip_list.append(f)

        return skip_list

    def _start_logging(self, filename):
        #will get the logging instance going
        loglevel_config = 'logging.%s' % self.loglevel

        #i'd like the stdout to be under another logging name than 'con_out'
        console_log_level = 25  #between INFO and WARNING
        quiet = self.quiet
        logging.addLevelName(console_log_level, "CONSOLE")

        def con_out(self, message, *args, **kws):   # pragma: no cover
            if not quiet:
                self._log(console_log_level, message, args, **kws)

        logging.Logger.con_out = con_out

        logging.basicConfig(filename=filename,
            level=eval(loglevel_config),
            format='%(asctime)s %(name)s %(levelname)s: %(message)s',
            datefmt = '%m-%d %H:%M:%S'
            )
        if not self.quiet: # pragma: no cover
            console = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s: %(message)s', '%m-%d %H:%M:%S')
            console.setFormatter(formatter)
            console.setLevel(console_log_level)
	self.logger = logging.getLogger(__name__)
        if not self.quiet:
            self.logger.addHandler(console) # pragma: no cover

        self.logger.con_out("Log File Created at %s" % filename)

    def _prep_environment(self):

        #we set up our various needed directory structures, etc.
        ran_uuid = str(uuid.uuid4().int)[:16]                                                 # 16 digit random string
        origin_path = os.path.join(self.report_dir, "soscleaner-origin-%s" % ran_uuid)        # the origin dir we'll copy the files into
        dir_path = os.path.join(self.report_dir, "soscleaner-%s" % ran_uuid)                  # the dir we will put our cleaned files into
        session = os.path.join(self.report_dir, "soscleaner-%s" % ran_uuid)                   # short-hand for the soscleaner session to create reports, etc.
        logfile = os.path.join(self.report_dir, "%s.log" % session)                           # the primary logfile

        return origin_path, dir_path, session, logfile, ran_uuid

    def _extract_sosreport(self, path):

        self.logger.con_out("Beginning SOSReport Extraction")
        compression_sig = self.magic.file(path).lower()
        if 'directory' in compression_sig:
            self.logger.info('%s appears to be a %s - continuing', path, compression_sig)
            # Clear out origin_path as we don't have one
            self.origin_path = None
            return path

        elif 'compressed data' in compression_sig:
            if compression_sig == 'xz compressed data':
                #This is a hack to account for the fact that the tarfile library doesn't
                #handle lzma (XZ) compression until version 3.3 beta
                try:
                    self.logger.info('Data Source Appears To Be LZMA Encrypted Data - decompressing into %s', self.origin_path)
                    self.logger.info('LZMA Hack - Creating %s', self.origin_path)
                    os.system('mkdir %s' % self.origin_path)
                    os.system('tar -xJf %s -C %s' % (path, self.origin_path))
                    return_path = os.path.join(self.origin_path, os.listdir(self.origin_path)[0])

                    return return_path

                except Exception,e: # pragma: no cover
                    self.logger.exception(e)
                    raise Exception('DecompressionError, Unable to decrypt LZMA compressed file %s', path)

            else:
                p = tarfile.open(path, 'r')

                self.logger.info('Data Source Appears To Be %s - decompressing into %s', compression_sig, self.origin_path)
                try:
                    p.extractall(self.origin_path)
                    return_path = os.path.join(self.origin_path, os.path.commonprefix(p.getnames()))

                    return return_path

                except Exception, e:    # pragma: no cover
                    self.logger.exception(e)
                    raise Exception("DeCompressionError: Unable to De-Compress %s into %s", path, self.origin_path)
        else:   # pragma: no cover
            raise Exception('CompressionError: Unable To Determine Compression Type')

    def _sub_ip(self, line):
        '''
        This will substitute an obfuscated IP for each instance of a given IP in a file
        This is called in the self._clean_line function, along with user _sub_* functions to scrub a given
        line in a file.
        It scans a given line and if an IP exists, it obfuscates the IP using _ip4_2_db and returns the altered line
        '''
        try:
            pattern = r"(((\b25[0-5]|\b2[0-4][0-9]|\b1[0-9][0-9]|\b[1-9][0-9]|\b[1-9]))(\.(\b25[0-5]|\b2[0-4][0-9]|\b1[0-9][0-9]|\b[1-9][0-9]|\b[0-9])){3})"
            ips = [each[0] for each in re.findall(pattern, line)]
            if len(ips) > 0:
                for ip in ips:
                    new_ip = self._ip4_2_db(ip)
                    self.logger.debug("Obfuscating IP - %s > %s", ip, new_ip)
                    line = line.replace(ip, new_ip)
            return line

        except Exception,e: # pragma: no cover
            self.logger.exception(e)
            raise e

    def _get_disclaimer(self):  # pragma: no cover
        #prints a disclaimer that this isn't an excuse for manual or any other sort of data verification

        self.logger.warning("%s is a tool to help obfuscate sensitive information from an existing sosreport." % self.name)
        self.logger.warning("Please review the content before passing it along to any third party.")

    def _create_hn_report(self):
        try:
            hn_report_name = os.path.join(self.report_dir, "%s-hostname.csv" % self.session)
            self.logger.con_out('Creating Hostname Report - %s', hn_report_name)
            hn_report = open(hn_report_name, 'w')
            hn_report.write('Obfuscated Hostname,Original Hostname\n')
            if self.hostname_count > 0:
                for k,v in self.hn_db.items():
                    hn_report.write('%s,%s\n' %(k,v))
            else:
                hn_report.write('None,None\n')
            hn_report.close()
            self.logger.info('Completed Hostname Report')

            self.hn_report = hn_report_name
        except Exception,e: #pragma: no cover
            self.logger.exception(e)
            raise Exception('CreateReport Error: Error Creating Hostname Report')

    def _create_dn_report(self):
        try:
            dn_report_name = os.path.join(self.report_dir, "%s-dn.csv" % self.session)
            self.logger.con_out('Creating Domainname Report - %s', dn_report_name)
            dn_report = open(dn_report_name, 'w')
            dn_report.write('Obfuscated Domain,Original Domain\n')
            if self.domain_count > 0:
                for k,v in self.dn_db.items():
                    dn_report.write('%s,%s\n' %(k,v))
            else:
                dn_report.write('None,None\n')
            dn_report.close()
            self.logger.info('Completed Domainname Report')

            self.dn_report = dn_report_name

        except Exception, e: # pragma: no cover
            self.logger.exception(e)
            raise Exception('CreateReport Error: Error Creating Domainname Report')

    def _create_ip_report(self):
        try:
            ip_report_name = os.path.join(self.report_dir, "%s-ip.csv" % self.session)
            self.logger.con_out('Creating IP Report - %s', ip_report_name)
            ip_report = open(ip_report_name, 'w')
            ip_report.write('Original IP,Obfuscated IP\n')
            for i in self.ip_db:
                ip_report.write('%s,%s\n' % (i[0],i[1]))
            ip_report.close()
            self.logger.info('Completed IP Report')

            self.ip_report = ip_report_name

        except Exception, e: # pragma: no cover
            self.logger.exception(e)
            raise e

    def _create_reports(self): # pragma: no cover

        self._create_ip_report()
        self._create_hn_report()
        self._create_dn_report()

    def _sub_hostname(self, line):
        '''
        This will replace the exact hostname and all instances of the domain name with the obfuscated alternatives.
        Example:
        '''
        try:
            for od,d in self.dn_db.items():
                # regex = re.compile(r'\w*\.%s' % d)
                regex = re.compile(r'(?![\W\-\:\ \.])[a-zA-Z0-9\-\_\.]*\.%s' % d)
                hostnames = [each for each in regex.findall(line)]
                if len(hostnames) > 0:
                    for hn in hostnames:
                        new_hn = self._hn2db(hn)
                        self.logger.debug("Obfuscating FQDN - %s > %s", hn, new_hn)
                        line = line.replace(hn, new_hn)
                        # replace any non-fqdn occurrences of the hostname
                        for entry in line.split():
                            # i don't remember what this does... but i'm going to leave it here for now...
                            if hn.startswith(entry): # pragma: no cover
                                line = line.replace(entry, new_hn.split('.')[0])
                # after we replace all of the hostnames, we will run back through the line and replace any root domain matches as well
                # should take care of issue #50
                line = line.replace(d, od)
            if self.hostname:
                line = line.replace(self.hostname, self._hn2db(self.hostname))  #catch any non-fqdn instances of the system hostname

            return line
        except Exception,e: # pragma: no cover
            self.logger.exception(e)
            raise e

    def _make_dest_env(self):
        '''
        This will create the folder in self.report_dir (defaults to /tmp) to store the sanitized files and populate it using shutil
        These are the files that will be scrubbed
        '''
        try:
            shutil.copytree(self.report, self.dir_path, symlinks=True, ignore=self._skip_file)

        except Exception, e:    #pragma: no cover
            self.logger.exception(e)
            raise Exception("DestinationEnvironment Error: Cannot Create Destination Environment")

    def _create_archive(self):
        '''This will create a tar.gz compressed archive of the scrubbed directory'''
        try:
            self.archive_path = os.path.join(self.report_dir, "%s.tar.gz" % self.session)
            self.logger.con_out('Creating SOSCleaner Archive - %s', self.archive_path)
            t = tarfile.open(self.archive_path, 'w:gz')
            for dirpath, dirnames, filenames in os.walk(self.dir_path):
                for f in filenames:
                    f_full = os.path.join(dirpath, f)
                    f_archive = f_full.replace(self.report_dir,'')
                    self.logger.debug('adding %s to %s archive', f_archive, self.archive_path)
                    t.add(f_full, arcname=f_archive)
        except Exception,e: #pragma: no cover
            self.logger.exception(e)
            raise Exception('CreateArchiveError: Unable to create Archive')

        self._clean_up()
        self.logger.info('Archiving Complete')
        self.logger.con_out('SOSCleaner Complete')
        if not self.quiet:  # pragma: no cover
            t.add(self.logfile, arcname=self.logfile.replace(self.report_dir,''))
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
        except Exception, e:    #pragma: no cover
            self.logger.exception(e)

    def _process_hosts_file(self):
        # this will process the hosts file more thoroughly to try and capture as many server short names/aliases as possible
        # could lead to false positives if people use dumb things for server aliases, like 'file' or 'server' or other common terms
        # this may be an option that can be enabled... --hosts or similar?

        try:
            if os.path.isfile(os.path.join(self.dir_path, 'etc/hosts')):
                with open(os.path.join(self.dir_path, 'etc/hosts')) as f:
                    self.logger.con_out("Processing hosts file for better obfuscation coverage")
                    data = f.readlines()
                    for line in data:
                        x = re.split('\ |\t', line.rstrip())    #chunk up the line, delimiting with spaces and tabs (both used in hosts files)
                        # we run through the rest of the items in a given line, ignoring the IP to be picked up by the normal methods
                        # skipping over the 'localhost' and 'localdomain' entries
                        for item in x[1:len(x)]:
                            if len(item) > 0:
                                if all(['localhost' not in item, 'localdomain' not in item]):
                                    new_host = self._hn2db(item)
                                    self.logger.debug("Added to hostname database through hosts file processing - %s > %s", item, new_host)
            else: # pragma: no cover
                self.logger.con_out("Unable to Process Hosts File. Hosts File Processing Disabled")

        except Exception, e:    #pragma: no cover
            self.logger.exception(e)

    def _domains2db(self):
        #adds any additional domainnames to the domain database to be searched for
        try:
            #we will add the root domain for an FQDN as well.
            if self.domainname is not None:
                self.dn_db[self.root_domain] = self.domainname
                self.logger.con_out("Obfuscated Domain Created - %s" % self.root_domain)

            split_root_d = self.root_domain.split('.')

            for d in self.domains:
                if d not in self.dn_db.values(): #no duplicates
                    d_number = len(self.dn_db)
                    o_domain = "%s%s.%s" % (split_root_d[0], d_number, split_root_d[1])
                    self.dn_db[o_domain] = d
                    self.logger.con_out("Obfuscated Domain Created - %s" % o_domain)

            self.domain_count = len(self.dn_db)
            return True

        except Exception, e: # pragma: no cover
            self.logger.exception(e)

    def _keywords2db(self):
        #processes optional keywords to add to be obfuscated
        try:
            if self.keywords:   # value is set to None by default
                k_count = 0
                for f in self.keywords:
                    if os.path.isfile(f):
                        with open(f, 'r') as klist:
                            for keyword in klist.readlines():
                                o_kw = "keyword%s" % k_count
                                self.kw_db[keyword.rstrip()] = o_kw
                                self.logger.con_out("Added Obfuscated Keyword - %s", o_kw)
                                k_count += 1
                        self.logger.con_out("Added Keyword Contents from file - %s", f)

                    else:
                        self.logger.con_out("%s does not seem to be a file. Not adding any keywords from" % f)

            self.kw_count = k_count

        except Exception, e: # pragma: no cover
            self.logger.exception(e)

    def _kw2db(self, keyword):
        #returns the obfuscated value for a keyword

        return self.kw_db[keyword]

    def _sub_keywords(self, line):
        # this will substitute out any keyword entries on a given line
        #try:
        if self.kw_count > 0:    # we have obfuscated keywords to work with
            for k in self.kw_db.keys():
                if k in line:
                    line = line.replace(k, self._kw2db(k))
                    self.logger.debug("Obfuscating Keyword - %s > %s", k, self._kw2db(k))

        return line

        '''except Exception, e: # pragma: no cover
            self.logger.exception(e)
            raise Exception('SubKeywordError: Unable to Substitute Keywords')'''

    def _get_hostname(self, hostname='hostname'):
        #gets the hostname and stores hostname/domainname so they can be filtered out later

        try:
            hostfile = os.path.join(self.dir_path, hostname)
            fh = open(hostfile, 'r')
            name_list = fh.readline().rstrip().split('.')
            hostname = name_list[0]
            if len(name_list) > 1:
                domainname = '.'.join(name_list[1:len(name_list)])
            else:
                domainname = None

            return hostname, domainname

        except IOError, e: #the 'hostname' file doesn't exist or isn't readable for some reason
            self.logger.warning("Unable to determine system hostname!!!")
            self.logger.warning("Automatic Hostname Data Obfuscation Will Not Occur!!!")
            self.logger.warning("To Remedy This Situation please enable the 'general' plugin when running sosreport")
            self.logger.warning("and/or be sure the 'hostname' symlink exists in the root directory of you sosreport")
            if not self.quiet: # pragma: no cover
                self.logger.exception(e)

            hostname = None
            domainname = None

            return hostname, domainname

        except Exception, e: # pragma: no cover
            self.logger.exception(e)
            raise Exception('GetHostname Error: Cannot resolve hostname from %s') % hostfile

    def _process_route_file(self):
        '''
        When there is a full sosreport, this will parse the output from the route command to populate self.net_db
        '''
        try:
            route_path = os.path.join(self.dir_path, 'route')
            if os.path.exists(route_path):
                fh = open(route_path, 'r')
                self.logger.info("Found route file. Auto-adding routed networks.")
                data = fh.readlines()[2:]   # skip the first 2 header lines and get down to the data
                for line in data:
                    x = line.split()
                    if not x[0] == '0.0.0.0':   # skip the default gateway
                        net_string = "%s/%s" % (x[0],x[2])
                        self._ip4_add_network(net_string)
                        self.logger.debug("Network Added by Auto-Route Processing.")
                fh.close()
            else:
                self.logger.info("No route file found. Unable to auto-add routed networks for this system.")
        except Exception, e: # pragma: no cover
            self.logger.exception(e)
            raise e

    def _ip4_new_obfuscate_net(self, netmask):
        '''
        This will return a new IPv4 Network Object for a newly obfuscated network
        '''
        try:
            # this is going to get hacky
            start_point = self.default_net.broadcast + 1    # this will return an IPv4Address object that is 129.0.0.0
            x = start_point.compressed.split('.')  # break it apart
            new_octet = str(int(x[0]) + self.net_count)   # calculate the new first octet

            self.net_count += 1
            new_net_string = "%s.0.0.0/%s" % (new_octet, netmask)   # a new string to create the new obfuscated network object
            retval = IPv4Network(new_net_string)

            return retval

        except Exception, e:    # pragma: no cover
            self.logger.exception(e)
            raise e

    def _ip4_parse_network(self, network):
        '''
        This will take the input values and return useable objects from them.
        Generated:
        an IPv4Network object for the original network
        a string value for the subnet mask that is used to create the obfuscated network
        '''
        try:
            net = IPv4Network(network)
            subnet = str(net.prefixlen)

            return net, subnet

        except Exception, e:    # pragma: no cover
            self.logger.exception(e)
            raise e

    def _ip4_network_in_db(self, network):
        '''
        This will return True if a network already exists in net_db
        It is used in _ip4_add_network to ensure we don't get duplicate network entries
        '''
        try:
            if any(network in x for x in self.net_db):
                return True
            return False

        except Exception, e:    # pragma: no cover
            self.logger.exception(e)
            raise e

    def _add_loopback_network(self):
        '''
        This will add an entry into the needed databases to keep loopback addresses somewhat sane. They will be obfuscated, but within the loopback numberspace.
        So more of a shuffler than anything else.
        '''
        try:
            self.logger.info("Adding Entry to Network Metadata Database - 127.0.0.0")
            self.net_metadata['127.0.0.0'] = dict()
            self.net_metadata['127.0.0.0']['host_count'] = 0

            lb_net = IPv4Network('127.0.0.0/8')
            loopback_entry = (lb_net, lb_net)
            self.net_db.append(loopback_entry)
            self.logger.con_out("Creating Loopback Network Entry")

        except Exception, e:    # pragma: no cover
            self.logger.exception(e)
            raise Exception(e)

    def _ip4_add_network(self, network):
        '''
        This will take any networks specified via the command-line parameters as well as the routes file (if present)
        and create obfuscated networks for each of them.
        This is called within self._process_route_file as well as in self.clean_report
        '''
        try:
            net, netmask = self._ip4_parse_network(network)

            if not self._ip4_network_in_db(net): # make sure we don't have duplicates
                new_net = self._ip4_new_obfuscate_net(netmask)    # the obfuscated network
                new_entry = (net, new_net)

                self.net_db.append(new_entry)
                self.logger.con_out("Created New Obfuscated Network - %s" % new_net.with_prefixlen)

                self.net_metadata[new_net.network.compressed] = dict()
                self.logger.info("Adding Entry to Network Metadata Database - %s" % new_net.with_prefixlen)
                self.net_metadata[new_net.network.compressed]['host_count'] = 0
            else:
                self.logger.info("Network already exists in database. Not obfuscating. - %s" % network)

        except Exception, e:    # pragma: no cover
            self.logger.exception(e)
            raise Exception(e)

    def _ip4_find_network(self, ip):
        '''
        This will take an IP address and return back the obfuscated network that it belongs to
        This is called by the _ip4_2_db function
        The value returned is a string that is the network address for the given network - IPv4Network.network.compressed
        This can be used to create a new obfuscated IP address for this value
        '''
        try:
            ip = IPv4Address(ip)    # re-cast as an IPv4 object
            network = self.default_net.network
            for net in self.net_db:
                if ip in net[0]:
                    network = net[1].network   # we have a match! We'll return the proper obfuscated network

            return network

        except Exception, e: # pragma: no cover
            self.logger.exception(e)
            raise e

    def _ip4_in_db(self, ip):
        '''
        Returns True if an IP is found the the obfuscation database
        Returns False otherwise
        The ip parameter is an IPv4Address object
        This function is called from within _ip4_2_db
        '''
        try:
            if any(ip in x for x in self.ip_db):
                return True
            return False

        except Exception, e: # pragma: no cover
            self.logger.exception(e)
            raise e

    def _ip4_2_db(self, orig_ip):
        '''
        adds an IP address to the IP database and returns the obfuscated entry, or returns the
        existing obfuscated IP entry
        '''
        try:
            if self._ip4_in_db(orig_ip):    # the IP exists already in the database
                data = dict(self.ip_db)     # http://stackoverflow.com/a/18114565/263834
                obf_ip = data[orig_ip]      # we'll pull the existing obfuscated IP from the database

                return obf_ip.compressed

            else:   # it's a new database, so we have to create a new obfuscated IP for the proper network and a new ip_db entry
                net = self._ip4_find_network(orig_ip)   # get the network information
                self.net_metadata[net.compressed]['host_count'] += 1
                # take the network and increment the number of hosts to get to the next available IP
                obf_ip = IPv4Address(net) + self.net_metadata[net.compressed]['host_count']
                self.ip_db.append((orig_ip, obf_ip))

                return obf_ip.compressed

        except Exception as e:    # pragma: no cover
            self.logger.exception(e)
            raise

    def _hn2db(self, hn):
        '''
        This will add a hostname for a hostname for an included domain or return an existing entry
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
            o_domain = self.root_domain
            for od,d in self.dn_db.items():
                if d in hn:
                    o_domain = od
            new_hn = "host%s.%s" % (self.hostname_count, o_domain)
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
        except Exception, e: # pragma: no cover
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

        new_line = self._sub_ip(l)                  # IP substitution
        new_line = self._sub_hostname(new_line)     # Hostname substitution
        new_line = self._sub_keywords(new_line)     # Keyword Substitution

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

            except Exception, e: # pragma: no cover
                self.logger.exception(e)
                raise Exception("CleanFile Error: Cannot Open File For Reading - %s" % f)

            try:
                if len(data) > 0:
                    new_fh = open(f, 'w')
                    for line in tmp_file:
                        new_fh.write(line)
                    new_fh.close()
            except Exception, e: # pragma: no cover
                self.logger.exception(e)
                raise Exception("CleanFile Error: Cannot Write to New File - %s" % f)

            finally:
                tmp_file.close()

    def _add_extra_files(self, files):
        '''if extra files are to be analyzed with an sosreport, this will add them to the origin path to be analyzed'''

        try:
            for f in files:
                self.logger.con_out("adding additional file for analysis: %s"  % f)
                fname = os.path.basename(f)
                f_new = os.path.join(self.dir_path, fname)
                shutil.copyfile(f,f_new)
        except IOError, e:
            self.logger.con_out("ExtraFileError: %s is not readable or does not exist. Skipping File" % f)
            self.logger.exception(e)
            pass
        except Exception, e:    # pragma: no cover
            self.logger.exception(e)
            raise Exception("ExtraFileError: Unable to Process Extra File - %s" % f)

    def _clean_files_only(self, files):
        ''' if a user only wants to process one or more specific files, instead of a full sosreport '''
        try:
            if not (os.path.exists(self.origin_path)):
                self.logger.info("Creating Origin Path - %s" % self.origin_path)
                os.makedirs(self.origin_path) # create the origin_path directory
            if not (os.path.exists(self.dir_path)):
                self.logger.info("Creating Directory Path - %s" % self.dir_path)
                os.makedirs(self.dir_path)    # create the dir_path directory
            self._add_extra_files(files)

        except OSError, e: # pragma: no cover
            if e.errno == errno.EEXIST:
                pass
            else:   # pragma: no cover
                self.logger.exception(e)
                raise e

        except Exception, e:    # pragma: no cover
            self.logger.exception(e)
            raise Exception("CleanFilesOnlyError: unable to process")

    def clean_report(self, options, sosreport): # pragma: no cover
        '''this is the primary function, to put everything together and analyze an sosreport'''

        if options.report_dir: # override the default location for artifacts (/tmp)
            if os.path.isdir(options.report_dir):
                self.report_dir = options.report_dir
        self.origin_path, self.dir_path, self.session, self.logfile, self.uuid = self._prep_environment()
        self._start_logging(self.logfile)
        self._check_uid() #make sure it's soscleaner is running as root
        self._get_disclaimer()
        self._add_loopback_network()
        if options.networks:    # we have defined networks
            self.networks = options.networks
            for network in options.networks:
                self._ip4_add_network(network)
        if options.domains:
            self.domains = options.domains
        if options.keywords:
            self.keywords = options.keywords
            self._keywords2db()
        if not sosreport:
            if not options.files:
                raise Exception("Error: You must supply either an sosreport and/or files to process")

            self.logger.con_out("No sosreport supplied. Only processing specific files")
            if not options.networks:
                self.logger.con_out("No sosreport supplied and no networks specified. All IP addresses will be obfuscated into the same default subnet")
            self._clean_files_only(options.files)

        else:   # we DO have an sosreport to analyze
            self.report = self._extract_sosreport(sosreport)
            self._make_dest_env()   # create the working directory
            if options.hostname_path:
                self.hostname, self.domainname = self._get_hostname(options.hostname_path)
            else:
                self.hostname, self.domainname = self._get_hostname()
            self._process_route_file()
            if options.files:
                self._add_extra_files(options.files)

            if self.hostname:   # if we have a hostname that's not a None type
                self.hn_db['host0'] = self.hostname     # we'll prime the hostname pump to clear out a ton of useless logic later

            self._process_hosts_file()  # we'll take a dig through the hosts file and make sure it is as scrubbed as possible

        self._domains2db()
        files = self._file_list(self.dir_path)
        self.logger.con_out("IP Obfuscation Network Created - %s", self.default_net.compressed)
        self.logger.con_out("*** SOSCleaner Processing ***")
        self.logger.info("Working Directory - %s", self.dir_path)
        for f in files:
            self.logger.debug("Cleaning %s", f)
            self._clean_file(f)
        self.logger.con_out("*** SOSCleaner Statistics ***")
        self.logger.con_out("IP Addresses Obfuscated - %s", len(self.ip_db))
        self.logger.con_out("Hostnames Obfuscated - %s" , len(self.hn_db))
        self.logger.con_out("Domains Obfuscated - %s" , len(self.dn_db))
        self.logger.con_out("Total Files Analyzed - %s", self.file_count)
        self.logger.con_out("*** SOSCleaner Artifacts ***")
        self._create_reports()
        self._create_archive()

        return_data = [self.archive_path, self.logfile, self.ip_report]
        if self.hostname:
            return_data.append(self.hn_report)
        if len(self.dn_db) >= 1:
            return_data.append(self.dn_report)

        return return_data
