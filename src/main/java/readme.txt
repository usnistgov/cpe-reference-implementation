*************************************************************************

       		 CPE Reference Implementation

		          README 
 	    
 	   Copyright (c) 2011, The MITRE Corporation

*************************************************************************

The MITRE Corporation developed the Common Platform Enumeration (CPE) 
Reference Implementation to demonstrate the usability of the CPE 
Matching and Naming Algorithms, as described in the CPE Matching 
Specification version 2.3 and CPE Naming Specification version 2.3. 
The source for the CPE Reference Implementation s freely available for 
reference use. This document describes the steps you need to build the
CPE Reference Implementation.

You may download the CPE Reference Implementation to any computer you wish, 
and to as many computers as you wish.  

BY USING THE CPE REFERENCE IMPLEMENTATION, YOU SIGNIFY YOUR ACCEPTANCE OF 
THE TERMS AND CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO 
NOT USE THE CPE REFERENCE IMPLEMENTATION.  SEE THE TERMS.TXT FILE INCLUDED
WITH THE CPE REFERENCE IMPLEMENTATION.


OVERVIEW
--------

See http://cpe.mitre.org for information about the Common Platform 
Enumeration standard. 

The following source packages are included in this release:

org.mitre.cpe.common  
- contains functions common to both the naming and matching packages

org.mitre.cpe.matching 
- contains classes related to the CPE matching algorithm

org.mitre.cpe.naming  
- contains classes related to the CPE naming algorithms

Build Instructions
-------------------

Required Software
   - JDK (http://www.oracle.com/technetwork/java/javase/downloads/index.html)
   - Apache Ant (http://ant.apache.org/) or Apache Maven (http://maven.apache.org/)

Ant Build
=========	
Run Ant using the build.xml supplied in this release.  The Ant script will 
compile all Java source files under the src/ directory and generate 3 
sample JAR files in the dist/ directory.

Maven Build
===========
Run Maven using the pom.xml supplied in this release.  The Maven build 
compile all Java source files under the src/ directory and generate a 
single JAR file in the target/ directory.

This implementation has been built and tested using the Java Platform 
Standard Edition 6 JDK, Apache Ant 1.8 and Apache Maven 2.2.1 on Microsoft Windows 7.  

Run Instructions
-----------------

After building using the build.xml file, navigate to the dist/ directory. There 
will be 3 JAR files, one corresponding to each main function in the source code.  
The main functions are found in:
   - org.mitre.cpe.naming.CPENameBinder
   - org.mitre.cpe.naming.CPENameUnbinder
   - org.mitre.cpe.matching.CPENameMatcher   

To run the JAR files and see the output from the sample main functions, 
use "java -jar filename.jar", replacing filename.jar with one of the generated JAR files.

