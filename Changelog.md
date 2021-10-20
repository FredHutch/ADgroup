# ADgroup Changelog

Please update this file when making changes to ADgroup.py

## [1.0.2] Oct 20, 2021
  * bug gidNumber not set during create group.  Issues with decoding objectSid

## [1.0.1] Oct 15, 2021
 
  * bug fix: Path to ADgroup.ini was relative and only worked from the project folder.
  * reformat to pass flake8
  * AD displayName outputs last, first.  Create new field: DisplayName, with First Last
  * Add --version argument

## [1.0.0] Oct 1, 2021
Initial release.  ADgroup is a refactoring of fhgroup.py. 

  * convert from Python 2 to 3
  * refactor into class library
  * remove referances to Fred Hutch
  * Move site specific configuration into INI file
  * increase ldap error checking
  * where possible update to LDAP3
  * Public Publish to Github
  * Add new features:  --org, --user, --group and option: --full
  * Search user by UID or uidName
  * Search group by GID or gidName
