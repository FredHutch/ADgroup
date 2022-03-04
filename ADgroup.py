#!/usr/bin/env python3

"""
    ADgroup.py manage security groups in Active Directory from kerberized Linux Systems

2022.02.08
2021.10.09 fix bug with DisplayName. Users with more than one comma in their name.
2021.09.14 John Dey jfdey@fredhutch.org john@fuzzdog.com
           Convert from Python2 to Python3
           ldap3 Attribute values are returned as byte strings must be decoded to utf-8
           add user and group arguments

Dirk Petersen dipeit@gmail.com 2013
"""

import sys
import os
import getpass
import ssl
from ldap3 import Server, Connection, Tls
from ldap3 import SASL, SUBTREE, KERBEROS
from ldap3 import MODIFY_ADD, MODIFY_DELETE
from ldap3.core.exceptions import LDAPException, LDAPEntryAlreadyExistsResult
from gssapi.raw.misc import GSSError
from argparse import SUPPRESS, ArgumentParser
import logging
import configparser
import json

__version__ = '1.1.0'
__date__ = 'Feb 15, 2022'
__maintainer__ = 'John Dey jfdey@fredhutch.org'


logging.basicConfig(
    format="%(levelname)s [%(funcName)s:%(lineno)s] %(message)s", level=logging.WARN
)


class ldapOps:
    def __init__(self, debug):
        if debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug("debug enabled")

        self.read_config()
        self.lcon = self.ldap_gss_init()

        self.curruser = getpass.getuser()
        if self.isMemberOf(self.curruser, self.AdminGroup):
            logging.debug("user: {} is member of the Admin group.: {}".format(
                    self.curruser, self.AdminGroup))
        else:
            print("Apparently you are not member of any administrative security groups."
                  " You will not be able to create or change AD groups.")

    def unbind(self):
        self.lcon.unbind()
        logging.debug('result: {}'.format(self.lcon.result))

    def abort(self, msg):
        """
           End our session and close the communication to the server
        """
        print(msg, file=sys.stderr)
        self.unbind()
        raise SystemExit

    def read_config(self):
        """read INI style configuration file"""
        config = configparser.ConfigParser()
        file_path = os.path.dirname(os.path.realpath(__file__))
        config_path = os.path.join(file_path, 'ADgroup.ini')
        logging.debug('using ini file: {}'.format(config_path))
        try:
            config.read(config_path)
        except configparser.Error:
            print('could not read ini')
            raise SystemExit
        self.AdminGroup = config["Admin"]["admingroup"]
        self.ADServer = config["AD"]["adserver"]
        self.ADSearchBase = config["AD"]["adsearchbase"]
        self.CreateOU = config["OU"]["createou"]
        self.EmpolyeeAttrs = json.loads(config.get("Attrs", "empolyee"))
        self.GroupAttrs = json.loads(config.get("Attrs", "group"))
        logging.debug("ADServer: {}".format(self.ADServer))
        logging.debug("CreateOU: {}".format(self.CreateOU))

    def ldap_gss_init(self):
        """ Use SASL Kerberos connection, optional connect methods could be used
        return_empty_attributes parameter to True
        """
        tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        server = Server(self.ADServer, use_ssl=True, tls=tls)
        try:
            lcon = Connection(server, authentication=SASL, client_strategy='SYNC',
                              sasl_mechanism=KERBEROS)
        except LDAPException as err:
            print("Error LDAP connection. ADServer URL: {}".format(err))
            raise SystemExit
        try:
            sync = lcon.bind()
        except GSSError as err:
            err_msg = str(err)
            if 'Ticket expired' in err_msg:
                print('Ticket expired; use kinit to get a new Kerberos ticket')
            else:
                print(err_msg)
            raise SystemExit
        if not sync:
            logging.error('bind result: {}'.format(self.lcon.result))
            raise SystemExit
        logging.debug('SASL Authorization Identity: {}'.format(lcon.extend.standard.who_am_i()))
        return lcon

    def groupChangeMembers(self, groupname, samlist=[], changemode="add"):
        """ Add or remove members from Storage group """
        groupdn = self.groupGetDN(groupname)
        ldaplist = ""
        for user in samlist:
            ldaplist += "(sAMAccountName=" + user + ")"
        ldapfilter = ("(&(|(sAMAccountType=805306368)(objectCategory=group))"
                      "(|" + ldaplist + "))")
        sync = self.lcon.search(search_base=self.ADSearchBase,
                                search_filter=ldapfilter, search_scope=SUBTREE, attributes=[])
        if not sync or self.lcon.result['result'] != 0:
            logging.error('search failed: {}\nfilter: {}'.format(self.lcon.result, ldapfilter))
            self.abort()
        for result in self.lcon.response:
            if 'dn' in result:
                memberDN = result['dn']
            else:
                continue
            if changemode == "add":
                change_member = {'member': [(MODIFY_ADD, [memberDN])]}
            elif changemode == "remov":
                change_member = {'member': [(MODIFY_DELETE, [memberDN])]}
            try:
                self.lcon.modify(groupdn, change_member)
            except LDAPEntryAlreadyExistsResult:
                logging.error("User {}, already Exists in group: {}.".format(samlist, groupname))
                return
            except LDAPException as err:
                errstr = err[0]["desc"]
                print(("Error changing memberhsip of '{}' "
                       "in group: {}".format(result[1]["sAMAccountName"][0], errstr)))
            if self.lcon.result['result'] == 0:
                print('successfully {}ed "{}" to/from group "{}"'.format(
                        changemode, memberDN, groupname))

    def groupCreate(self, samname):
        """
           --create
           create group with unique GID based on objectSid
           this is a two step process. Create the storage object first then add the gidnumber to
           the storage group object.
        """
        grp_dn = "CN=" + samname + "," + self.CreateOU
        grp_attrs = {
            'objectClass': ['top', 'group'],
            'cn': samname,
            'sAMAccountName': samname,
            'description': 'created by ' + self.curruser + ' with ADgroup',
        }
        sync = self.lcon.add(dn=grp_dn, attributes=grp_attrs)
        if sync is not True:
            logging.error("Create group: {}.\nFailed: {}".
                          format(grp_dn, self.lcon.result['description']))
            return

        # Create and add gidNumber to group object
        gid = self.gidNumberSet(grp_dn)
        print('created group "{}" with gidNumber {}.\nOU: {}.\n'
              'Use chgrp {} </my/folder> to apply permissions.'.format(
                    samname, gid, self.CreateOU, gid)
              )
        print("Make sure you add at least one member to the new group.\n"
              "After that you may have to wait up to 15 min until users can access")

    def groupDelete(self, group):
        """
           --delete  Delete group
        """
        dn = self.groupGetDN(group)
        sync = self.lcon.delete(dn)
        if not sync:
            logging.error("Delete group: {} failed\n{}".format(group, self.lcon.result))
        else:
            print("Delete Group success for: {}\n{}".format(group, self.lcon.result))

    def gidNumberSet(self, DN):
        """ return the GID after groupCreate
            Create a consistent gidNumber based on ObjectSID of the group
            add 1,000,000 to the last six digits of the ObjectSID
        """
        sync = self.getAttr(DN, ["objectSid"])
        objectSid = str(self.lcon.entries[0].objectSid)
        logging.debug('objectSid of new group: {}'.format(objectSid))
        tail = objectSid.split('-')[-1]
        GID = str(int(tail) + 1000000)
        add_member = {'gidNumber': [(MODIFY_ADD, [GID])]}
        sync = self.lcon.modify(DN, add_member)
        if sync is not True:
            logging.error("Add attribute to group: {}.".format(DN))
            logging.error("Failed - error: {}".format(self.lcon.result['description']))
            return False
        return GID

    def groupGetMembers(self, target, full):
        """
           --list of members from class "group"
        """
        dn = self.groupGetDN(target)
        ldapfilter = "(&(memberof={}))".format(dn)
        if full:
            Attrs = ['*']
        else:
            Attrs = ["name", "sAMAccountName"]
        sync = self.lcon.search(search_base=self.ADSearchBase,
                                search_filter=ldapfilter,
                                search_scope=SUBTREE,
                                attributes=Attrs)
        if not sync or self.lcon.result['result'] != 0:
            self.abort('search error DN: {}'.format(dn))
        for result in self.lcon.entries:
            name = str(result['sAMAccountName'])
            if full:
                mail = displayName = ''
                if 'mail' in result:
                    mail = str(result.mail)
                if 'displayName' in result:
                    displayName = result.displayName
                print('{:25}{:40}{}'.format(name, mail, displayName))
            else:
                print(name)

    def groupGetDN(self, samname):
        """ return DN for group
            Python3
        """
        ldapfilter = "(&(objectCategory=group)(sAMAccountName=%s))" % samname
        Attrs = ["distinguishedName"]
        sync = self.lcon.search(search_base=self.ADSearchBase,
                                search_filter=ldapfilter,
                                search_scope=SUBTREE,
                                attributes=Attrs)
        if not sync:
            self.abort("search results: {}".format(self.lcon.result))
        logging.debug("results: {}".format(self.lcon.response))
        if len(self.lcon.response) == 2:
            return self.lcon.response[0]['dn']
        else:
            print('group not found: {}'.format(samname))
            self.unbind()
            raise SystemExit

    def userGetDN(self, samname):
        """Return DN as usable form for query, ie. Escape valid LDAP filter characters."""
        ldapfilter = "(&(objectClass=person)(sAMAccountName=%s))" % samname
        Attrs = ['sAMAccountName']
        sync = self.lcon.search(search_base=self.ADSearchBase,
                                search_filter=ldapfilter,
                                search_scope=SUBTREE,
                                attributes=Attrs)
        if not sync or self.lcon.result['result'] != 0:
            logging.error("search result: {}".format(self.lcon.result))
            raise SystemExit
        logging.debug("entries: {}".format(self.lcon.entries))
        return self.lcon.response[0]['dn']

    def escapeDN(self, dn):
        """The LDAP filter specification assigns special meaning to the following characters:
         * ( ) backslach NUL that should be escaped with a backslash followed by the two character
         ASCII hexadecimal representation of the character when used in a search filter (rfc2254)
        """
        DN = str(dn)
        DN = DN.replace('\\', '\\5c')
        DN = DN.replace('(', '\\28')
        DN = DN.replace(')', '\\29')
        DN = DN.replace('*', '\\2A')
        return DN

    def groupGetEntry(self, gid, full):
        """
            --group
            show full AD record for a group
        """
        if gid.isnumeric():
            ldapfilter = '(&(objectCategory=group)(gidNumber={}))'.format(gid)
        else:
            ldapfilter = '(&(objectCategory=group)(cn={}))'.format(gid)
        if full:
            Attrs = ["*"]
        else:
            Attrs = self.GroupAttrs
        sync = self.lcon.search(search_base=self.ADSearchBase,
                                search_filter=ldapfilter,
                                search_scope=SUBTREE,
                                attributes=Attrs)
        if not sync:
            logging.error("result: {}".format(self.lcon.result))
            return
        self.printResponse()

    def userGetEntry(self, uid, full):
        """
           --user  uidNumber or name
        """
        if uid.isnumeric():
            ldapfilter = '(uidNumber={})'.format(uid)
        else:
            ldapfilter = "(&(objectClass=person)(uid={}))".format(uid)
        if full:
            Attrs = ["*"]
        else:
            Attrs = self.EmpolyeeAttrs
        sync = self.lcon.search(search_base=self.ADSearchBase,
                                search_filter=ldapfilter,
                                search_scope=SUBTREE,
                                attributes=Attrs)
        if not sync or self.lcon.result['result'] != 0:
            logging.error("result: {}".format(self.lcon.result))
            return
        self.printResponse()

    def printResponse(self):
        """ print response from ldap3 search """
        if len(self.lcon.entries) == 0:
            print('no search results')
            return
        for obj in self.lcon.response:
            if 'attributes' not in obj:
                continue
            for k, v in obj['attributes'].items():
                if type(v) is list and len(v) > 0:
                    print('{:>30}: {}'.format(k, v[0]))
                    for values in v[1:]:
                        print('{:32}{}'.format(' ', values))
                else:
                    print('{:>30}: {}'.format(k, v))

    def getAttr(self, dn, attrs):
        """ search by DN for <attrs>.
            <dn> type str
            <attrs> list of str
        """
        ldapfilter = "(distinguishedName=" + dn + ")"
        sync = self.lcon.search(self.ADSearchBase,
                                search_filter=ldapfilter,
                                search_scope=SUBTREE,
                                attributes=attrs)
        if not sync:
            logging.error("result: {}".format(self.lcon.result))
            raise SystemExit
        if len(self.lcon.entries) == 0:
            print('No resesult for: {}'.format(dn))
            self.unbind()
            raise SystemExit

    def organization(self, user_name):
        """
           display the orgainization above <user_name>
           End contidition is not consistent for all organizations
        """
        DN = self.userGetDN(user_name)
        self.getAttr(DN, ['manager'])
        managerDN = self.escapeDN(self.lcon.entries[0].manager)
        Attrs = ['sAMAccountName', 'displayName', 'title', 'manager', 'distinguishedName']
        while True:
            self.getAttr(managerDN, Attrs,)
            if len(self.lcon.entries) == 0:
                break
            dresult = dict(self.lcon.response[0]['attributes'])
            (last, first) = dresult['displayName'].split(',')
            fixed = first.strip() + ' ' + last
            print('{} - {} ({})'.format(fixed, dresult['title'],
                                        dresult['sAMAccountName']))
            if 'manager' in dresult:
                managerDN = self.escapeDN(dresult['manager'])
                if dresult['manager'] == dresult['distinguishedName']:
                    break

    def userSearch(self, target):
        """
            --search <uid> | displayName
            Search for Class Person where target is part of the <user> or <displayName>
            objects.
            return uid and Displayname
        """
        Attrs = ["displayName", "gecos", "uid", "uidNumber", "cn", "mail"]
        ldapfilter = "(&(objectClass=organizationalPerson)(objectClass=user)"
        ldapfilter += "(|(uid=*{}*)(displayName=*{}*)))".format(target, target)
        sync = self.lcon.search(search_base=self.ADSearchBase,
                                search_filter=ldapfilter,
                                search_scope=SUBTREE,
                                attributes=Attrs)
        if not sync or self.lcon.result['result'] != 0:
            logging.error('search error: {}'.format(self.lcon.result))
            return
        for result in self.lcon.entries:
            try:
                uid = str(result.uid)
            except NameError:
                uid = ''
            try:
                mail = str(result.mail)
            except NameError:
                mail = ''
            if 'uidNumber' in result:
                uidNumber = str(result.uidNumber)
            else:
                uidNumber = ''
            print("{:16}{:12}{:26}{}".format(uid, uidNumber, result.displayName[0], mail))

    def isMemberOf(self, user, group):
        """ check if Class person <user> is a member of <group>
            there are two ways of performing this query.
            look at memberOf for user OR query Class group for membership
        """
        self.memberOf(user)
        for obj in self.lcon.response:
            if 'attributes' not in obj:
                break
            attrs = obj['attributes']
            if 'memberOf' in attrs:
                logging.debug("{} is a memberOf: {}".format(user, attrs['memberOf']))
                for member in attrs['memberOf']:
                    cn = member.split(",")[0][3:]
                    if cn == group:
                        return True
                        print('=== Found ===')
        return False

    def memberGet(self, target):
        """
           --memberOf <uid>
           list memberOf objects for Class person by sAMAccountName
        """
        self.memberOf(target)
        for obj in self.lcon.response:
            if 'attributes' not in obj:
                continue
            attrs = obj['attributes']
            if 'memberOf' in attrs:
                logging.debug('{} is a memberOf: {}'.format(target, attrs['memberOf']))
                for member in attrs['memberOf']:
                    print(member.split(",")[0][3:])

    def memberOf(self, user):
        """ list group membership for a user where group
        is in the OU Security Group
        """
        Attrs = ["displayName", "memberOf"]
        ldapfilter = "(&(objectClass=person)(sAMAccountName={}))".format(user)
        sync = self.lcon.search(search_base=self.ADSearchBase,
                                search_filter=ldapfilter,
                                search_scope=SUBTREE,
                                attributes=Attrs)
        if not sync:
            logging.error('search error: {}'.format(self.lcon.result))
            raise SystemExit


def parse_arguments():
    """ Parse command-line arguments. """

    help = (
        "Manage Active Directory Security Groups from Linux CLI "
        "and use Kerberos tickets to authorized group managers."
    )
    parser = ArgumentParser(prog="ADgroup", description=help)
    parser.add_argument(
        '--version', '-V', action='version', version="%(prog)s " + __version__ + ' - ' + __date__
    )
    parser.add_argument(
        "--debug", "-d", dest="debug", action="store_false", default=False,
        help="Enable debug messages",
    )
    parser.add_argument(
        "--full", dest="full", action="store_true", default=False,
        help='Show additional information when used with "user", "group" and "list" commands.',
    )
    create_help = "Create security group and set the gidNumber based on objectSid"
    parser.add_argument(
        "--create", "-c", dest="create", action="store_true", default=False,
        help=create_help,
    )
    parser.add_argument("--delete", dest="delete", action="store_true", default="", help=SUPPRESS)
    parser.add_argument(
        "--list", "-l", dest="list", action="store_true", default=False,
        help="list the members of the security group in the positional argument",
    )
    parser.add_argument(
        "--add", "-a", dest="members2add", action="store", default="",
        help=("comma delimited list of users or groups to be added to this group. "
              "e.g. --add jdoe,lcorey,big-users"),
    )
    parser.add_argument(
        "--remove", "-r", dest="members2remove", action="store", default="",
        help=("Remove members from group. Comma delimited list of users or groups "
              "to be removed from this group. e.g. --remove jdoe,lcorey,big-users"),
    )
    parser.add_argument(
        "--user", "-u", dest="user", action="store_true", default=False,
        help=("List AD record for user."),
    )
    parser.add_argument(
        "--org", dest="org", action="store_true", default=False,
        help=("List organization of user."),
    )
    parser.add_argument(
        "--group", "-g", dest="group", action="store_true", default=False,
        help=("List AD record for group."),
    )
    parser.add_argument(
        "--search", "-s", dest="search", action="store_true", default=False,
        help=("Search uid and displayName fields."),
    )
    parser.add_argument(
        "--memberOf", dest="memberOf", action="store_true", default=False,
        help=("List storage groups for user"),
    )
    parser.add_argument(
        "groupname", nargs='?', type=str,
        help=("AccountName of the AD security group to be created or changed. "),
    )
    args = parser.parse_args()
    return args


def main():
    args = parse_arguments()
    try:
        ad = ldapOps(args.debug)
    except SystemExit:
        return 1

    if args.create:
        if not args.groupname.endswith("_grp"):
            args.groupname = args.groupname + "_grp"
        ad.groupCreate(args.groupname)
    elif args.delete:
        ad.groupDelete(args.groupname)
    elif args.members2add:
        args.members2add = args.members2add.replace(" ", ",")
        ad.groupChangeMembers(args.groupname, args.members2add.split(","), changemode="add")
    elif args.members2remove:
        args.members2remove = args.members2remove.replace(" ", ",")
        ad.groupChangeMembers(args.groupname, args.members2remove.split(","), changemode="remov")
    elif args.user:
        ad.userGetEntry(args.groupname, args.full)
    elif args.group:
        ad.groupGetEntry(args.groupname, args.full)
    elif args.org:
        ad.organization(args.groupname)
    elif args.list:
        ad.groupGetMembers(args.groupname, args.full)
    elif args.search:
        ad.userSearch(args.groupname)
    elif args.memberOf:
        ad.memberGet(args.groupname)
    else:
        print('No arguement given. Try --help')
    ad.unbind()


if __name__ == "__main__":
    sys.exit(main())
