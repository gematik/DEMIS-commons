<img align="right" width="250" height="47" src="media/Gematik_Logo_Flag.png"/> <br/>

# demis-commons

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
       <ul>
        <li><a href="#quality-gates">Quality Gates</a></li>
        <li><a href="#release-notes">Release Notes</a></li>
      </ul>
	</li>
    <li><a href="#security-policy">Security Policy</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

## About The Project

This project is a collection of common utilities for DEMIS Projects, such as:

* load of Keystore/Truststore
* fetch of JWT Token from a remote endpoint
* definition of Proxy configurations
* definition of TLS Context

There's the possibility to deactivate the TLS Hostname Verification when the environment
variable `ENABLE_HOSTNAME_VERIFICATION` is set to `false` (e.g. for testing purposes), by default the verification is
always activated.

**Beware**: 

The Environment variable `ENABLE_HOSTNAME_VERIFICATION`, when set to `true`, will cause the set of the
following Java Property: `jdk.internal.httpclient.disableHostnameVerification` to be set to `true`, disabling then the
Hostname Verification for all the HTTP Communications in an application.

### Quality Gates

[![Quality Gate Status](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acommons&metric=alert_status&token=sqb_ddf7277a67838d45942ed255ee216c1fb6fc125a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acommons)
[![Vulnerabilities](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acommons&metric=vulnerabilities&token=sqb_ddf7277a67838d45942ed255ee216c1fb6fc125a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acommons)
[![Bugs](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acommons&metric=bugs&token=sqb_ddf7277a67838d45942ed255ee216c1fb6fc125a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acommons)
[![Code Smells](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acommons&metric=code_smells&token=sqb_ddf7277a67838d45942ed255ee216c1fb6fc125a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acommons)
[![Lines of Code](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acommons&metric=ncloc&token=sqb_ddf7277a67838d45942ed255ee216c1fb6fc125a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acommons)
[![Coverage](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acommons&metric=coverage&token=sqb_ddf7277a67838d45942ed255ee216c1fb6fc125a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acommons)

### Release Notes

See [ReleaseNotes](ReleaseNotes.md) for all information regarding the (newest) releases.

## Security Policy
If you want to see the security policy, please check our [SECURITY.md](.github/SECURITY.md).

## Contributing
If you want to contribute, please check our [CONTRIBUTING.md](.github/CONTRIBUTING.md).

## License
EUROPEAN UNION PUBLIC LICENCE v. 1.2

EUPL © the European Union 2007, 2016

Following terms apply:

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.

2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions::

    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.

    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.

    3. The software is the result of research and development activities, therefore not necessarily quality assured and without the character of a liable product. For this reason, gematik does not provide any support or other user assistance (unless otherwise stated in individual cases and without justification of a legal obligation). Furthermore, there is no claim to further development and adaptation of the results to a more current state of the art.

3. Gematik may remove published results temporarily or permanently from the place of publication at any time without prior notice or justification.

4. Please note: Parts of this code may have been generated using AI-supported technology.’ Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.

## Contact

E-Mail to [OSPO](mailto:ospo@gematik.de?subject=[OSPO]%20demis-commons)