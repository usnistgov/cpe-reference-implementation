# CPE Reference Implementation
[![Gitter](https://img.shields.io/gitter/room/usnistgov-cpe-ri/community.svg?style=flat-square)](https://gitter.im/usnistgov-cpe-ri/community)

This Common Platform Enumeration (CPE) Reference Implementation demonstrates the usability of the CPE Naming and Matching Algorithms, as described in the [CPE Naming Specification](https://csrc.nist.gov/publications/detail/nistir/7695/final) version 2.3 and [CPE Matching Specification](https://csrc.nist.gov/publications/detail/nistir/7696/final) version 2.3. 

This code was [orginally developed](https://cpe.mitre.org/specification/#downloads) by the MITRE Corporation and is now maintained by NIST.

For information about the Common Platform Enumeration standard, please visit the [project site](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe/). 

The following source packages are included in this release:

- gov.nist.secauto.cpe.common: contains functions common to both the naming and matching packages

   This package contains the following class:

   - gov.nist.secauto.cpe.common.WellFormedName: provides methods to construct an unbound CPE name

- gov.nist.secauto.cpe.naming: contains classes related to the CPE naming algorithms

   This package contains the following classes:

   - gov.nist.secauto.cpe.naming.CPENameBinder: provides methods to bind a WellFormedName to the CPE URI and formatted string forms
   - gov.nist.secauto.cpe.naming.CPENameUnbinder: provides methods to unbind a CPE URI or formatted string into a WellFormedName

- gov.nist.secauto.cpe.matching: contains classes related to the CPE matching algorithm

   This package contains the following class:

   - gov.nist.secauto.cpe.matching.CPENameMatcher: provides methods to test a match between two different CPE names


