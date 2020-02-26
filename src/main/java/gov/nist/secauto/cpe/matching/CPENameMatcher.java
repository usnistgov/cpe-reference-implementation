/**
 * Portions of this software was developed by employees of the National Institute
 * of Standards and Technology (NIST), an agency of the Federal Government and is
 * being made available as a public service. Pursuant to title 17 United States
 * Code Section 105, works of NIST employees are not subject to copyright
 * protection in the United States. This software may be subject to foreign
 * copyright. Permission in the United States and in foreign countries, to the
 * extent that NIST may hold copyright, to use, copy, modify, create derivative
 * works, and distribute this software and its documentation without fee is hereby
 * granted on a non-exclusive basis, provided that this notice and disclaimer
 * of warranty appears in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER
 * EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY
 * THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM
 * INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE
 * SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT
 * SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT,
 * INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM,
 * OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY,
 * CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR
 * PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT
 * OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER.
 */
// Copyright (c) 2011, The MITRE Corporation

// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
//    * Redistributions of source code must retain the above copyright notice, this list
//      of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above copyright notice, this
//      list of conditions and the following disclaimer in the documentation and/or other
//      materials provided with the distribution.
//    * Neither the name of The MITRE Corporation nor the names of its contributors may be
//      used to endorse or promote products derived from this software without specific
//      prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
// SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
// OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
// TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package gov.nist.secauto.cpe.matching;

import gov.nist.secauto.cpe.common.LogicalValue;
import gov.nist.secauto.cpe.common.Utilities;
import gov.nist.secauto.cpe.common.WellFormedName;
import gov.nist.secauto.cpe.common.WellFormedName.Attribute;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The CPENameMatcher is an implementation of the CPE Matching algorithm, as specified in the CPE
 * Matching Standard version 2.3.
 * 
 * @see <a href= "https://doi.org/10.6028/NIST.IR.7696">NISTIR 7696 Section 7</a>
 * 
 * @author <a href="mailto:jkraunelis@mitre.org">Joshua Kraunelis</a>
 * @author <a href="mailto:david.waltermire@nist.gov">David Waltermire</a>
 */
public class CPENameMatcher {
  private CPENameMatcher() {
    // disable construction
  }

  /**
   * Tests two Well Formed Names for disjointness.
   * 
   * @param source
   *          Source WFN
   * @param target
   *          Target WFN
   * @return true if the names are disjoint, false otherwise
   */
  public static boolean isDisjoint(WellFormedName source, WellFormedName target) {
    // if any pairwise comparison is disjoint, the names are disjoint.
    Map<WellFormedName.Attribute, Relation> resultList = compareWFNs(source, target);
    for (Relation result : resultList.values()) {
      if (Relation.DISJOINT.equals(result)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Tests two Well Formed Names for equality.
   * 
   * @param source
   *          Source WFN
   * @param target
   *          Target WFN
   * @return true if the names are equal, false otherwise
   */
  public static boolean isEqual(WellFormedName source, WellFormedName target) {
    // if every pairwise comparison is equal, the names are equal.
    Map<WellFormedName.Attribute, Relation> resultList = compareWFNs(source, target);
    for (Relation result : resultList.values()) {
      if (!(Relation.EQUAL.equals(result))) {
        return false;
      }
    }
    return true;
  }

  /**
   * Tests if the target Well Formed Name is a subset of the source Well Formed Name.
   * 
   * @param source
   *          Source WFN
   * @param target
   *          Target WFN
   * @return true if the target is a subset of the source, false otherwise
   */
  public static boolean isSubset(WellFormedName source, WellFormedName target) {
    // if any comparison is anything other than subset or equal, then target is
    // not a subset of source.
    Map<WellFormedName.Attribute, Relation> resultList = compareWFNs(source, target);
    for (Relation result : resultList.values()) {
      if (!(Relation.SUBSET.equals(result)) && !(Relation.EQUAL.equals(result))) {
        return false;
      }
    }
    return true;
  }

  /**
   * Tests if the target Well Formed name is a superset of the source Well Formed Name.
   * 
   * @param source
   *          Source WFN
   * @param target
   *          Target WFN
   * @return true if the target is a superset of the source, false otherwise
   */
  public static boolean isSuperset(WellFormedName source, WellFormedName target) {
    // if any comparison is anything other than superset or equal, then target is
    // not
    // a superset of source.
    Map<WellFormedName.Attribute, Relation> resultList = compareWFNs(source, target);
    for (Relation result : resultList.values()) {
      if ((!Relation.SUPERSET.equals(result)) && (!Relation.EQUAL.equals(result))) {
        return false;
      }
    }
    return true;
  }

  /**
   * Compares each attribute value pair in two Well Formed Names.
   * 
   * @param source
   *          Source WFN
   * @param target
   *          Target WFN
   * @return A Hashtable mapping attribute string to attribute value Relation
   */
  public static Map<WellFormedName.Attribute, Relation> compareWFNs(WellFormedName source, WellFormedName target) {
    Map<WellFormedName.Attribute, Relation> result
        = new LinkedHashMap<WellFormedName.Attribute, Relation>(Attribute.values().length);
    for (WellFormedName.Attribute attribute : Attribute.values()) {
      result.put(attribute, compare(source.get(attribute), target.get(attribute)));
    }
    return result;
  }

  /**
   * Compares an attribute value pair.
   * 
   * @param source
   *          Source attribute value.
   * @param target
   *          Target attribute value.
   * @return The relation between the two attribute values.
   */
  private static Relation compare(Object source, Object target) {
    // matching is case insensitive, convert strings to lowercase.
    if (isString(source)) {
      source = Utilities.toLowercase((String) source);
    }
    if (isString(target)) {
      target = Utilities.toLowercase((String) target);
    }

    // Unquoted wildcard characters yield an undefined result.
    if (isString(target) && Utilities.containsWildcards((String) target)) {
      return Relation.UNDEFINED;
    }
    // If source and target values are equal, then result is equal.
    if (source.equals(target)) {
      return Relation.EQUAL;
    }

    // Check to see if source or target are Logical Values.
    LogicalValue lvSource = null;
    LogicalValue lvTarget = null;
    if (source instanceof LogicalValue) {
      lvSource = (LogicalValue) source;
    }
    if (target instanceof LogicalValue) {
      lvTarget = (LogicalValue) target;
    }

    // If Logical Values are equal, result is equal.
    if (lvSource != null && lvTarget != null && lvSource.equals(lvTarget)) {
      return Relation.EQUAL;
    }

    // If source value is ANY, result is a superset.
    if (lvSource != null && LogicalValue.ANY.equals(lvSource)) {
      return Relation.SUPERSET;
    }
    // If target value is ANY, result is a subset.
    if (lvTarget != null && LogicalValue.ANY.equals(lvTarget)) {
      return Relation.SUBSET;
    }
    // If source or target is NA, result is disjoint.
    if (lvSource != null && LogicalValue.NA.equals(lvSource)) {
      return Relation.DISJOINT;
    }

    if (lvTarget != null && LogicalValue.NA.equals(lvTarget)) {
      return Relation.DISJOINT;
    }
    // only Strings will get to this point, not LogicalValues
    return compareStrings((String) source, (String) target);
  }

  /**
   * Compares a source string to a target string, and addresses the condition in which the source
   * string includes unquoted special characters. It performs a simple regular expression match, with
   * the assumption that (as required) unquoted special characters appear only at the beginning and/or
   * the end of the source string. It also properly differentiates between unquoted and quoted special
   * characters.
   * 
   * @return Relation between source and target Strings.
   */
  private static Relation compareStrings(String source, String target) {
    int start = 0;
    int end = Utilities.strlen(source);
    int begins = 0;
    int ends = 0;

    if (Utilities.substr(source, 0, 1).equals("*")) {
      start = 1;
      begins = -1;
    } else {
      while ((start < Utilities.strlen(source)) && (Utilities.substr(source, start, start + 1).equals("?"))) {
        start = start + 1;
        begins = begins + 1;
      }
    }
    if ((Utilities.substr(source, end - 1, end).equals("*")) && (isEvenWildcards(source, end - 1))) {
      end = end - 1;
      ends = -1;
    } else {
      while ((end > 0) && Utilities.substr(source, end - 1, end).equals("?") && (isEvenWildcards(source, end - 1))) {
        end = end - 1;
        ends = ends + 1;
      }
    }

    source = Utilities.substr(source, start, end);

    int index = -1;
    int leftover = Utilities.strlen(target);
    Relation retval = Relation.DISJOINT;
    while (leftover > 0) {
      index = Utilities.indexOf(target, source, index + 1);
      if (index == -1) {
        break;
      }
      int escapes = Utilities.countEscapeCharacters(target, 0, index);
      if ((index > 0) && (begins != -1) && (begins < (index - escapes))) {
        break;
      }
      escapes = Utilities.countEscapeCharacters(target, index + 1, Utilities.strlen(target));
      leftover = Utilities.strlen(target) - index - escapes - Utilities.strlen(source);
      if ((leftover > 0) && ((ends != -1) && (leftover > ends))) {
        continue;
      } else {
        retval = Relation.SUPERSET;
        break;
      }
    }
    return retval;
  }

  /**
   * Searches a string for the backslash character.
   * 
   * @param str
   *          string to search in
   * @param idx
   *          end index
   * @return true if the number of backslash characters is even, false if odd
   */
  private static boolean isEvenWildcards(String str, int idx) {
    int result = 0;
    while ((idx > 0) && (Utilities.strchr(str, '\\', idx - 1)) != -1) {
      idx = idx - 1;
      result = result + 1;
    }
    return Utilities.isEvenNumber(result);
  }

  /**
   * Tests if an Object is an instance of the String class.
   * 
   * @param arg
   *          the Object to test
   * @return true if arg is a String, false if not
   */
  private static boolean isString(Object arg) {
    if (arg instanceof String) {
      return true;
    } else {
      return false;
    }
  }
}
