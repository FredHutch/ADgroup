# ADgroup
SciComp Python Package for Managing AD Groups

Create, add/remove members to ADgroups.  ADgroup requires an admin class of users who have
the privileges to create and manage AD.


### Usage
ADgroup --help to show all command-line options.

### Install and Configure

Copy ADgroup.demo to ADgroup.ini and configure. Add your local sites AD server and domain.  The
"admingroup" is an OU whose users have privileges to make AD changes. The default filters should work for most AD installations.


ADgroup.py requires Python3 and will work with the default Python installed with most Linux distributions. Copy ADgroup.sh and rename to ADgroup. Create a symbolic link from a bin directory to ADgroup. ADgroup is a shell wrapper used to call ADgroup.py. Configure ADgroup wrapper for local Python path.
