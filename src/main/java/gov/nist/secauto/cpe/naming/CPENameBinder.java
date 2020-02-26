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

package gov.nist.secauto.cpe.naming;

import gov.nist.secauto.cpe.common.LogicalValue;
import gov.nist.secauto.cpe.common.Utilities;
import gov.nist.secauto.cpe.common.WellFormedName;

/**
 * The CPENameBinder class is a simple implementation of the CPE Name binding algorithm, as
 * specified in the CPE Naming Standard version 2.3.
 * 
 * @see <a href= "https://doi.org/10.6028/NIST.IR.7695">NISTIR 7695 Section 6.1.2</a>
 * @see <a href= "https://doi.org/10.6028/NIST.IR.7695">NISTIR 7695 Section 6.2.2</a>
 * 
 * @author <a href="mailto:jkraunelis@mitre.org">Joshua Kraunelis</a>
 * @author <a href="mailto:david.waltermire@nist.gov">David Waltermire</a>
 */
public class CPENameBinder {

  private CPENameBinder() {
    // disable construction
  }

  // Define the attributes that correspond to the seven components in a v2.2. CPE.
  public static final WellFormedName.Attribute[] URI_ATTRIBUTES
      = { WellFormedName.Attribute.PART, WellFormedName.Attribute.VENDOR, WellFormedName.Attribute.PRODUCT,
          WellFormedName.Attribute.VERSION, WellFormedName.Attribute.UPDATE, WellFormedName.Attribute.EDITION,
          // requires packing
          WellFormedName.Attribute.LANGUAGE };

  /**
   * Binds a {@link WellFormedName} object to a URI.
   * 
   * @param wfn
   *          WellFormedName to be bound to URI
   * @return URI binding of WFN
   */
  public static String bindToURI(WellFormedName wfn) {

    // Initialize the output with the CPE v2.2 URI prefix.
    String uri = "cpe:/";

    // Iterate over the well formed name
    for (WellFormedName.Attribute attr : URI_ATTRIBUTES) {
      String value = "";
      if (WellFormedName.Attribute.EDITION.equals(attr)) {
        // Call the pack() helper function to compute the proper
        // binding for the edition element.
        String edition = bindValueForURI(wfn.get(WellFormedName.Attribute.EDITION));
        String swEdition = bindValueForURI(wfn.get(WellFormedName.Attribute.SW_EDITION));
        String targetSoftware = bindValueForURI(wfn.get(WellFormedName.Attribute.TARGET_SW));
        String targetHardware = bindValueForURI(wfn.get(WellFormedName.Attribute.TARGET_HW));
        String other = bindValueForURI(wfn.get(WellFormedName.Attribute.OTHER));
        value = pack(edition, swEdition, targetSoftware, targetHardware, other);
      } else {
        // Get the value for attr in wfn, then bind to a string
        // for inclusion in the URI.
        value = bindValueForURI(wfn.get(attr));
      }
      // Append value to the URI then add a colon.
      uri = Utilities.strcat(uri, value, ":");
    }
    // Return the URI string, with trailing colons trimmed.
    return trim(uri);
  }

  /**
   * Top-level function used to bind WFN w to formatted string.
   * 
   * @param wfn
   *          WellFormedName to bind
   * @return Formatted String
   */
  public static String bindToFS(WellFormedName wfn) {
    // Initialize the output with the CPE v2.3 string prefix.
    String fs = "cpe:2.3:";
    for (WellFormedName.Attribute attr : WellFormedName.Attribute.values()) {
      String value = bindValueForFS(wfn.get(attr));
      fs = Utilities.strcat(fs, value);
      // add a colon except at the very end
      if (!WellFormedName.Attribute.OTHER.equals(attr)) {
        fs = Utilities.strcat(fs, ":");
      }
    }
    return fs;
  }

  /**
   * Convert the value v to its proper string representation for insertion to formatted string.
   * 
   * @param value
   *          value to convert
   * @return Formatted value
   */
  private static String bindValueForFS(Object value) {
    if (value instanceof LogicalValue) {
      LogicalValue logicalValue = (LogicalValue) value;
      // The value NA binds to a blank.
      if (LogicalValue.ANY.equals(logicalValue)) {
        return "*";
      }
      // The value NA binds to a single hyphen.
      if (LogicalValue.NA.equals(logicalValue)) {
        return "-";
      }
    }
    return processQuotedChars((String) value);
  }

  /**
   * Inspect each character in the provided string, and escape as required.
   * <p>
   * Certain non-alpha characters pass thru without escaping into the result, but most retain
   * escaping.
   * 
   * @param str
   *          the string to process
   * @return the processed string result
   */
  private static String processQuotedChars(String str) {
    String result = "";
    int index = 0;
    while (index < Utilities.strlen(str)) {
      String ch = Utilities.substr(str, index, index + 1);
      if (!ch.equals("\\")) {
        // unquoted characters pass thru unharmed.
        result = Utilities.strcat(result, ch);
      } else {
        // escaped characters are examined.
        String nextchr = Utilities.substr(str, index + 1, index + 2);
        // the period, hyphen and underscore pass unharmed.
        if (nextchr.equals(".") || nextchr.equals("-") || nextchr.equals("_")) {
          result = Utilities.strcat(result, nextchr);
          index = index + 2;
          continue;
        } else {
          // all others retain escaping.
          result = Utilities.strcat(result, "\\", nextchr);
          index = index + 2;
          continue;
        }
      }
      index = index + 1;
    }
    return result;
  }

  /**
   * Converts a value to the proper string for including in a CPE v2.2-conformant URI. The logical
   * value ANY binds to the blank in the 2.2-conformant URI.
   * 
   * @param value
   *          the value to be converted
   * @return the converted string
   */
  private static String bindValueForURI(Object value) {
    if (value instanceof LogicalValue) {
      LogicalValue logicalValue = (LogicalValue) value;
      // The value NA binds to a blank.
      if (LogicalValue.ANY.equals(logicalValue)) {
        return "";
      }
      // The value NA binds to a single hyphen.
      if (LogicalValue.NA.equals(logicalValue)) {
        return "-";
      }
    }

    // If we get here, we're dealing with a string value.
    return transformForURI((String) value);
  }

  /**
   * Scans an input string and performs a series of transformations to convert the string to a bound
   * URI form.
   * <p>
   * The following transformations are performed:
   * <ul>
   * <li>Pass alphanumeric characters thru untouched</li>
   * <li>Percent-encode quoted non-alphanumerics as needed</li>
   * <li>Unquoted special characters are mapped to their special forms</li>
   * </ul>
   * 
   * @param str
   *          string to be transformed
   * @return transformed string
   */
  private static String transformForURI(String str) {
    String result = "";
    int idx = 0;

    while (idx < Utilities.strlen(str)) {
      // Get the idx'th character of s.
      String thischar = Utilities.substr(str, idx, idx + 1);
      // Alphanumerics (incl. underscore) pass untouched.
      if (Utilities.isAlphanum(thischar)) {
        result = Utilities.strcat(result, thischar);
        idx = idx + 1;
        continue;
      }
      // Check for escape character.
      if (thischar.equals("\\")) {
        idx = idx + 1;
        String nxtchar = Utilities.substr(str, idx, idx + 1);
        result = Utilities.strcat(result, pctEncode(nxtchar));
        idx = idx + 1;
        continue;
      }
      // Bind the unquoted '?' special character to "%01".
      if (thischar.equals("?")) {
        result = Utilities.strcat(result, "%01");
      }
      // Bind the unquoted '*' special character to "%02".
      if (thischar.equals("*")) {
        result = Utilities.strcat(result, "%02");
      }
      idx = idx + 1;
    }
    return result;
  }

  /**
   * Returns the appropriate percent-encoding of character c. Certain characters are returned without
   * encoding.
   * 
   * @param ch
   *          the single character string to be encoded
   * @return the percent encoded string
   */
  private static String pctEncode(String ch) {
    if (ch.equals("!")) {
      return "%21";
    }
    if (ch.equals("\"")) {
      return "%22";
    }
    if (ch.equals("#")) {
      return "%23";
    }
    if (ch.equals("$")) {
      return "%24";
    }
    if (ch.equals("%")) {
      return "%25";
    }
    if (ch.equals("&")) {
      return "%26";
    }
    if (ch.equals("'")) {
      return "%27";
    }
    if (ch.equals("(")) {
      return "%28";
    }
    if (ch.equals(")")) {
      return "%29";
    }
    if (ch.equals("*")) {
      return "%2a";
    }
    if (ch.equals("+")) {
      return "%2b";
    }
    if (ch.equals(",")) {
      return "%2c";
    }
    // bound without encoding.
    if (ch.equals("-")) {
      return ch;
    }
    // bound without encoding.
    if (ch.equals(".")) {
      return ch;
    }
    if (ch.equals("/")) {
      return "%2f";
    }
    if (ch.equals(":")) {
      return "%3a";
    }
    if (ch.equals(";")) {
      return "%3b";
    }
    if (ch.equals("<")) {
      return "%3c";
    }
    if (ch.equals("=")) {
      return "%3d";
    }
    if (ch.equals(">")) {
      return "%3e";
    }
    if (ch.equals("?")) {
      return "%3f";
    }
    if (ch.equals("@")) {
      return "%40";
    }
    if (ch.equals("[")) {
      return "%5b";
    }
    if (ch.equals("\\")) {
      return "%5c";
    }
    if (ch.equals("]")) {
      return "%5d";
    }
    if (ch.equals("^")) {
      return "%5e";
    }
    if (ch.equals("`")) {
      return "%60";
    }
    if (ch.equals("{")) {
      return "%7b";
    }
    if (ch.equals("|")) {
      return "%7c";
    }
    if (ch.equals("}")) {
      return "%7d";
    }
    if (ch.equals("~")) {
      return "%7d";
    }
    // Shouldn't reach here, return original character
    return ch;
  }

  /**
   * Packs the values of the five arguments into the single edition component. If all the values are
   * blank, the function returns a blank.
   * 
   * @param edition
   *          edition string
   * @param swEdition
   *          software edition string
   * @param targetSoftware
   *          target software string
   * @param targetHardware
   *          target hardware string
   * @param other
   *          other edition information string
   * @return the packed string, or blank
   */
  private static String pack(String edition, String swEdition, String targetSoftware, String targetHardware,
      String other) {
    if (swEdition.equals("") && targetSoftware.equals("") && targetHardware.equals("") && other.equals("")) {
      // All the extended attributes are blank, so don't do
      // any packing, just return ed.
      return edition;
    }
    // Otherwise, pack the five values into a single string
    // prefixed and internally delimited with the tilde.
    return Utilities.strcat("~", edition, "~", swEdition, "~", targetSoftware, "~", targetHardware, "~", other);
  }

  /**
   * Removes trailing colons from the URI.
   * 
   * @param str
   *          the string to be trimmed
   * @return the trimmed string
   */
  private static String trim(String str) {
    String s1 = Utilities.reverse(str);
    int idx = 0;
    for (int i = 0; i != Utilities.strlen(s1); i++) {
      if (Utilities.substr(s1, i, i + 1).equals(":")) {
        idx = idx + 1;
      } else {
        break;
      }
    }
    // Return the substring after all trailing colons,
    // reversed back to its original character order.
    return Utilities.reverse(Utilities.substr(s1, idx, Utilities.strlen(s1)));
  }
}
