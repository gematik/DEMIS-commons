<img align="right" width="250" height="47" src="../Gematik_Logo_Flag.png"/> <br/>

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
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#security-policy">Security Policy</a></li>
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

**Hint:**

To perform the tests, sample data must be added to the files:

* nginx.truststore.template: 
  * Needs to be filled with a CA-Certificate and an End-Entity-Certificate which is issued by the CA.
    Set the path to the p12 from the EE-Certificate in adapter.app.properties (idp.lab.authcertkeystore).
* adapter.app.properties.template

Afterwards, please remove the ".template" suffix so that the files can be used in the code.

### Quality Gates

[![Quality Gate Status](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acommons&metric=alert_status&token=sqb_ddf7277a67838d45942ed255ee216c1fb6fc125a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acommons)
[![Vulnerabilities](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acommons&metric=vulnerabilities&token=sqb_ddf7277a67838d45942ed255ee216c1fb6fc125a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acommons)
[![Bugs](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acommons&metric=bugs&token=sqb_ddf7277a67838d45942ed255ee216c1fb6fc125a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acommons)
[![Code Smells](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acommons&metric=code_smells&token=sqb_ddf7277a67838d45942ed255ee216c1fb6fc125a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acommons)
[![Lines of Code](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acommons&metric=ncloc&token=sqb_ddf7277a67838d45942ed255ee216c1fb6fc125a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acommons)
[![Coverage](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acommons&metric=coverage&token=sqb_ddf7277a67838d45942ed255ee216c1fb6fc125a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acommons)

### Release Notes

See [ReleaseNotes](../ReleaseNotes.md) for all information regarding the (newest) releases.

## Contributing

If you want to contribute, please check our [CONTRIBUTING.md](CONTRIBUTING.md).

## Security Policy

If you want to see the security policy, please check our [SECURITY.md](SECURITY.md).

## License

EUROPEAN UNION PUBLIC LICENCE v. 1.2

EUPL © the European Union 2007, 2016

Copyright (c) 2023 gematik GmbH

See [LICENSE](../LICENSE.md).

## Contact

E-Mail to [DEMIS Entwicklung](mailto:demis-entwicklung@gematik.de?subject=[GitHub]%20Validation-Service)