#pf-identitystoreprovisioner-ldap

### Overview

PingFederate identity store provisioner to provision users into a generic LDAP data store.


### System Requirements / Dependencies

Requires:
 - PingFederate 7.2.x or higher
 - Apache Commons logging

 
### Installation
 
1. Compile the plugin in (refer to the [PingFederate server SDK documentation] for details on compiling PingFederate plug-ins)
2. Copy the resulting .jar file to the <pf_home>/server/default/deploy folder (on all nodes and admin instances).
3. Restart PingFederate
 
[PingFederate server SDK documentation]: http://documentation.pingidentity.com/display/PF/SDK+Developer%27s+Guide


### Configuration

Once the plug-in has been deployed and the PingFederate instance restarted, launch the PingFederate admin console.

When configuring the inbound provisioning settings in an SP Connection, select this provisioner from the list and refer to the inline documentation to configure.


### Disclaimer

This software is open sourced by Ping Identity but not supported commercially as such. Any questions/issues should go to the Github issues tracker or discuss on the [Ping Identity developer communities] . See also the DISCLAIMER file in this directory.

[Ping Identity developer communities]: https://community.pingidentity.com/collaborate