#!/usr/bin/env python3

"""
    ADgroup.py manage security groups in Active Directory from kerberized Linux Systems


2021.09.14 John Dey jfdey@fredhutch.org john@fuzzdog.com
           Convert from Python2 to Python3
           ldap3 Attribute values are returned as byte strings must be decoded to utf-8
           add user and group arguments

Dirk Petersen dipeit@gmail.com 2013
"""

import sys
import re
import getpass
import ldap
import ldap.sasl
import ldap.modlist
import ldap3
import argparse
import logging
import struct
import configparser
import json
import base64

__version__ = '1.0.0'
__date__ = 'Oct 1, 2021'
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
        if self.curruser in self.groupGetMembers(self.AdminGroup):  # AD.AdminGroup
            logging.debug("user: {} is member of the Admin group.: {}".format(
                    self.curruser, self.AdminGroup))
        else:
            print("Apparently you are not member of any administrative security groups."
                  " You will not be able to create or change AD groups.")

    def read_config(self):
        """read INI style configuration file"""
        config = configparser.ConfigParser()
        try:
            config.read("ADgroup.ini")
        except configparser.Error:
            print('could not read ini')
            raise SystemExit
        self.AdminGroup = config["Admin"]["admingroup"]

        self.ADServer = config["AD"]["adserver"]
        self.ADSearchBase = config["AD"]["adsearchbase"]
        self.ADSearchScope = ldap.SCOPE_SUBTREE

        self.CreateOU = config["OU"]["createou"]

        self.EmpolyeeAttrs = json.loads(config.get("Attrs", "empolyee"))
        self.GroupAttrs = json.loads(config.get("Attrs", "group"))
        logging.debug("ADServer: {}".format(self.ADServer))
        logging.debug("Empolyee Attrs: {}".format(self.EmpolyeeAttrs))

    def ldap_gss_init(self):
        try:
            lcon = ldap.initialize(self.ADServer, bytes_mode=False)
            lcon.set_option(ldap.OPT_REFERRALS, 0)
        except ldap.LDAPError as err:
            print("Error with ADServer URL: {}".format(err.args[0]))
            raise SystemExit
        auth = ldap.sasl.gssapi("")
        try:
            lcon.sasl_interactive_bind_s("", auth)
        except ldap.LDAPError as ldap_err:
            logging.debug("LDAPError: {}".format(ldap_err))
            err = dict(ldap_err.args[0])
            desc = info = None
            if "info" in err:
                info = err["info"]
                print("LDAP Error: {}".format(info))
                if "expired" in info:
                    print(" - Use kinit command to get new a Kerberos ticket.")
            elif "desc" in err:
                print("LDAP error: {}".format(desc)["desc"])
            raise SystemExit
        return lcon

    def groupChangeMembers(self, groupname, samlist=[], changemode="add"):
        groupdn = self.groupGetDN(groupname)
        changed = []
        adjective = 'to'
        if not groupdn:
            print("Group does not exist")
            return changed
        ldaplist = ""
        for user in samlist:
            ldaplist += "(sAMAccountName=" + user + ")"
        ldapfilter = ("(&(|(sAMAccountType=805306368)(objectCategory=group))"
                      "(|" + ldaplist + "))")
        Attrs = []
        r = self.lcon.search(self.ADSearchBase, self.ADSearchScope, ldapfilter, Attrs)
        result_type, Results = self.lcon.result(r, 60)
        for result in Results:
            if not result[0]:
                continue
            member = ldap3.utils.conv.to_raw(result[0], encoding="utf-8")
            if changemode == "add":
                change_member = [(ldap.MOD_ADD, "member", member)]
            elif changemode == "remov":
                change_member = [(ldap.MOD_DELETE, "member", member)]
                adjective = 'from'
            try:
                self.lcon.modify_s(groupdn, change_member)
                changed.append(result[0])
            except ldap.ALREADY_EXISTS as exists_err:
                print("Error: User {}, already Exists in group: {}.".format(samlist, groupname))
                return
            except ldap.LDAPError as err:
                errstr = err[0]["desc"]
                print(("Error changing memberhsip of '{}' "
                       "in group: {}".format(result[1]["sAMAccountName"][0], errstr)))
        if changed:
            print("successfully {}ed members {} group '{}':\n{}".format(
                        changemode, adjective, groupname, " \n".join(changed)))
            return True
        return False

    def groupCreate(self, samname):
        """ create group with unique GID based on objectSid
        """
        grp_dn = "CN=" + samname + "," + self.CreateOU
        grp_attrs = {}
        grp_attrs["objectClass"] = [bytes("top", "utf8"), bytes("group", "utf8")]
        grp_attrs["cn"] = bytes(samname, "utf8")
        grp_attrs["sAMAccountName"] = bytes(samname, "utf8")
        grp_attrs["description"] = bytes("(created by {} with ADgroup)".format(self.curruser), "utf8")
        grp_ldif = ldap.modlist.addModlist(grp_attrs)
        # Add the new group account
        errstr = ""
        try:
            self.lcon.add_s(grp_dn, grp_ldif)
        except ldap.LDAPError as err:
            if "desc" in err[0]:
                errstr = err[0]["desc"]
            if "info" in err[0]:
                errstr += err[0]["info"]
            print(("Error creating group object '{}': {}".format(grp_dn, errstr)))
            return False
        # Create and add gidNumber to group object
        gid = self.gidNumberSet(grp_dn)
        if gid:
            print(
                'created group "{}" with gidNumber {} in {}.\n'
                'Use chgrp {} </my/folder> to apply permissions.'.format(
                    samname, gid, self.CreateOU, gid
                )
            )
            return True
        else:
            print('GID not set')
            return False

    def gidNumberSet(self, DN):
        """ return the GID after groupCreate
            rewritten for Python3
            Create a consistent gidNumber based on ObjectSID
        """
        result = self.getAttr(DN, ["objectSid"])
        str_sid = self.convertSid(result[0][1])
        gidNumber = str(self.sidstr2gid(str_sid))
        ret = self.setGroupAttr(DN, "gidNumber", gidNumber)
        if ret is False:
            return ret
        else:
            return gidNumber

    def groupGetMembers(self, samname):
        """ return list of members from sAMAccountName, <samname>
            when sAMAccountName is a group
        """
        members = []
        dn = self.groupGetDN(samname)
        ldapfilter = "(&(memberof={}))".format(dn)
        Attrs = ["sAMAccountName"]
        r = self.lcon.search(self.ADSearchBase, self.ADSearchScope, ldapfilter, Attrs)
        result_type, Results = self.lcon.result(r, 60)
        for result in Results:
            if Attrs[0] in result[1]:
                members.append(result[1]["sAMAccountName"][0].decode("utf-8"))
        return members

    def modGroupAttr(self, samOrDn, attr, value):
        if not samOrDn.lower().startswith("cn="):
            samOrDn = self.groupGetDN(samOrDn)
        # grp_attrs = {}
        # grp_attrs[attr] = [bytes(value, "utf8")]
        # grp_ldif = ldap.modlist.addModlist(grp_attrs)
        myattr = [(ldap.MOD_REPLACE, attr, [bytes(value, "utf8")])]
        try:
            self.lcon.modify_s(samOrDn, myattr)
        except ldap.LDAPError as err:
            errstr = ''
            if "desc" in err[0]:
                errstr = err[0]["desc"]
            if "info" in err[0]:
                errstr += err[0]["info"]
            print(("Error setting Group Attr: object: [{}] Attr: [{}] err: {}".format(
                   samOrDn, attr, errstr)))
            return False
        return True

    def setGroupAttr(self, samOrDn, attr, value):
        if not samOrDn.lower().startswith("cn="):
            samOrDn = self.groupGetDN(samOrDn)
        myattr = [(ldap.MOD_ADD, attr, [bytes(value, "utf8")])]
        try:
            self.lcon.modify_s(samOrDn, myattr)
        except ldap.LDAPError as err:
            errstr = ''
            if "desc" in err[0]:
                errstr = err[0]["desc"]
            if "info" in err[0]:
                errstr += err[0]["info"]
            print(("Error setting Group Attr: object: [{}] Attr: [{}] err: {}".format(samOrDn, attr, errstr)))
            return False
        return True

    def groupGetDN(self, samname):
        """ return DN for group
            Python3
        """
        ldapfilter = "(&(objectCategory=group)(sAMAccountName=%s))" % samname
        Attrs = ["distinguishedName"]
        r = self.lcon.search(self.ADSearchBase, self.ADSearchScope, ldapfilter, Attrs)
        result_type, Results = self.lcon.result(r, 60)
        logging.debug("results: {}".format(Results[0][0]))
        return Results[0][0]

    def escapeDN(self, DN):
        """The LDAP filter specification assigns special meaning to the following characters:
         * ( ) backslach NUL that should be escaped with a backslash followed by the two character
         ASCII hexadecimal representation of the character when used in a search filter (rfc2254)
        """
        DN = DN.replace('\\', '\\5c')
        DN = DN.replace('(', '\\28')
        DN = DN.replace(')', '\\29')
        DN = DN.replace('*', '\\2A')
        return DN

    def userGetDN(self, samname):
        """Return DN as usable form for query, ie. Escape valid LDAP filter characters."""
        ldapfilter = "(&(objectClass=person)(sAMAccountName=%s))" % samname
        Attrs = ['sAMAccountName']
        r = self.lcon.search(self.ADSearchBase, self.ADSearchScope, ldapfilter, Attrs)
        result_type, Results = self.lcon.result(r, 60)
        DN = self.escapeDN(Results[0][0])
        logging.debug('result: {}'.format(DN))
        return DN

    def group_info(self, gid, full):
        """show full AD record for a group
        search
        """
        if gid.isnumeric():
            filter = '(&(objectCategory=group)(gidNumber={}))'.format(gid)
        else:
            filter = '(&(objectCategory=group)(sAMAccountName={}))'.format(gid)
        Attrs = ["*"]
        r = self.lcon.search(self.ADSearchBase, self.ADSearchScope, filter, Attrs)
        result_type, Results = self.lcon.result(r, 60)
        logging.debug('results: {}'.format(Results[0][0]))
        for result in Results:
            if not result[0]:
                break
            if full:
                for f in result[1]:
                    self.printkv(f, result[1][f])
            else:
                for f in self.GroupAttrs:
                    if f not in result[1]:
                        continue
                    self.printkv(f, result[1][f])

    def user_info(self, uid, full):
        """query AD by UID"""
        if uid.isnumeric():
            filter = '(uidNumber={})'.format(uid)
        else:
            filter = "(uid={})".format(uid)
        Attrs = self.EmpolyeeAttrs
        Attrs = ["*"]
        r = self.lcon.search(self.ADSearchBase, self.ADSearchScope, filter, Attrs)
        # print('Results: {}'.format(r))
        # print('[]'.format(lcon.entries))
        result_type, Results = self.lcon.result(r, 60)
        for result in Results:
            if not result[0]:
                continue
            if full:
                for f in result[1]:

                    self.printkv(f, result[1][f])
            else:
                for f in self.EmpolyeeAttrs:
                    if f not in result[1]:
                        continue
                    self.printkv(f, result[1][f])

    def printkv(self, k, v):
        """Print Key Value record"""
        for item in v:
            if k in ['objectSid', 'XobjectGUID']:
                objectSid = self.convertSid(v)
                print("    {}: decode({})".format(k, objectSid))
                gidNumber = self.sidstr2gid(objectSid)
                print("    {}: decode({})".format('GID', gidNumber))
            try:
                data = item.decode("utf-8")
            except UnicodeDecodeError:
                data = item
            if k in ["display", "distinguishedName"]:
                print(" -- {}: ".format(k), end="")
            else:
                print("    {}: ".format(k), end="")
            print("{} ".format(data), end="")
        print("")

    def getAttr(self, dn, attrs):
        """search on DN for a list attrs.
        <dn> type str
        <attrs> list of str
        Return array of attrs values converted to type str.
        """
        filter = "(distinguishedName=" + dn + ")"
        logging.debug('ldap.search: {} return Attrs: {}'.format(filter, attrs))
        try:
            q = self.lcon.search(self.ADSearchBase, self.ADSearchScope, filter, attrs)
        except Exception:
            logging.error('filter error: {}'.format(filter))
            return None
        except ldap.LDAPError as err:
            errstr = ''
            if "desc" in err[0]:
                errstr = err[0]["desc"]
            if "info" in err[0]:
                errstr += err[0]["info"]
        namesearch = self.lcon.result(q, 60)[1]
        logging.debug('attrs: {} result: {}'.format(attrs, namesearch))
        result = []
        if namesearch[0][0]:
            for attr in attrs:
                if attr in namesearch[0][1]:
                    try:
                        query_value = namesearch[0][1][attr][0].decode("utf-8")
                        logging.debug('decoded: {}'.format(namesearch[0][1][attr][0]))
                    except UnicodeDecodeError:
                        query_value = namesearch[0][1][attr][0]
                    result.append([attr, query_value])
        if len(result) is 0:
            return None
        else:
            return result

    def convertSid(self, sid_obj):
        """  convert base64 encoded objectSid to string representation """
        if hasattr(sid_obj, "__iter__"):
            sid = sid_obj[0]
        else:
            sid = sid_obj
        version = struct.unpack('B', sid[0:1])[0]
        # I do not know how to treat version != 1 (it does not exist yet)
        assert version == 1, version
        length = struct.unpack('B', sid[1:2])[0]
        authority = struct.unpack(b'>Q', b'\x00\x00' + sid[2:8])[0]
        string = 'S-%d-%d' % (version, authority)
        sid = sid[8:]
        assert len(sid) == 4 * length
        for i in range(length):
            value = struct.unpack('<L', sid[4*i:4*(i+1)])[0]
            string += '-%d' % value
        return string

    def sidstr2gid(self, sidstr):
        """ convert an active directory Sid string to a valid gid number
            for posix permission management
        """
        m = re.search(r"\d+$", sidstr)
        return int(m.group()) + 1000000

    def organization(self, user_name):
        """display the orgainization above <user_name>
        End contidition is not consistent for all organizations
        """
        DN = self.userGetDN(user_name)
        results = self.getAttr(DN, ['manager'])
        Attrs = ['sAMAccountName', 'displayName', 'title', 'manager', 'distinguishedName']
        managerDN = self.escapeDN(results[0][1])
        while True:
            results = self.getAttr(managerDN, Attrs,)
            if results is None:
                break
            dresult = dict(results)
            print('{} - {} ({})'.format(dresult['displayName'], dresult['title'],
                                        dresult['sAMAccountName']))
            if 'manager' in dresult:
                managerDN = self.escapeDN(dresult['manager'])
                if dresult['manager'] == dresult['distinguishedName']:
                    break


def parse_arguments():
    """ Parse command-line arguments. """

    help = (
        "Manage Active Directory Security Groups from Linux CLI "
        "and use Kerberos tickets to authorize group managers"
    )
    parser = argparse.ArgumentParser(prog="ADgroup", description=help)
    parser.add_argument(
        "--debug", "-d", dest="debug", action="store_true", default=False,
        help="Enable debug messages",
    )
    parser.add_argument(
        "--full", dest="full", action="store_true", default=False,
        help='Show all AD records when used with "user" and "list" commands.',
    )
    parser.add_argument(
        "groupname", type=str, default="",
        help=("AccountName of the AD security group to be created or changed. "),
    )
    create_help = "Create security group and set the gidNumber based on objectSid"
    parser.add_argument(
        "--create", "-c", dest="create", action="store_true", default=False,
        help=create_help,
    )
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
    args = parser.parse_args()
    if (not args.create and
            not args.members2add and
            not args.members2remove and
            not args.list and
            not args.user and
            not args.group and
            not args.org):
        parser.print_help()
        sys.exit(1)
    else:
        return args


def main():
    args = parse_arguments()
    try:
        ad = ldapOps(args.debug)
    except SystemExit:
        return 1

    repmsg = (
        "Make sure you add at least one member to the new group.\n"
        "After that you may have to wait up to 15 min until users can access "
    )
    if args.create:
        if not args.groupname.endswith("_grp"):
            args.groupname = args.groupname + "_grp"
        gid = ad.groupCreate(args.groupname)
        print(repmsg)
    elif args.members2add:
        args.members2add = args.members2add.replace(" ", ",")
        added = ad.groupChangeMembers(
            args.groupname, args.members2add.split(","), changemode="add"
        )
    elif args.members2remove:
        args.members2remove = args.members2remove.replace(" ", ",")
        removed = ad.groupChangeMembers(
            args.groupname, args.members2remove.split(","), changemode="remov"
        )
    elif args.user:
        ad.user_info(args.groupname, args.full)
    elif args.group:
        ad.group_info(args.groupname, args.full)
    elif args.org:
        ad.organization(args.groupname)
    elif args.list:
        members = ad.groupGetMembers(args.groupname)
        for m in members:
            print(m)


if __name__ == "__main__":
    sys.exit(main())
