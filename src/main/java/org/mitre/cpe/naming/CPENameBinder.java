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

package org.mitre.cpe.naming;

import org.mitre.cpe.common.LogicalValue;
import org.mitre.cpe.common.Utilities;
import org.mitre.cpe.common.WellFormedName;

import java.text.ParseException;

/**
 * The CPENameBinder class is a simple implementation of the CPE Name binding algorithm, as
 * specified in the CPE Naming Standard version 2.3.
 * 
 * See {@link <a href="http://cpe.mitre.org">cpe.mitre.org</a>} for more information.
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
          WellFormedName.Attribute.VERSION, WellFormedName.Attribute.UPDATE, WellFormedName.Attribute.EDITION, // requires
                                                                                                               // packing
          WellFormedName.Attribute.LANGUAGE };

  /**
   * Binds a {@link WellFormedName} object to a URI.
   * 
   * @param w
   *          WellFormedName to be bound to URI
   * @return URI binding of WFN
   */
  public static String bindToURI(WellFormedName w) {

    // Initialize the output with the CPE v2.2 URI prefix.
    String uri = "cpe:/";

    // Iterate over the well formed name
    for (WellFormedName.Attribute a : URI_ATTRIBUTES) {
      String v = "";
      if (WellFormedName.Attribute.EDITION.equals(a)) {
        // Call the pack() helper function to compute the proper
        // binding for the edition element.
        String ed = bindValueForURI(w.get(WellFormedName.Attribute.EDITION));
        String sw_ed = bindValueForURI(w.get(WellFormedName.Attribute.SW_EDITION));
        String t_sw = bindValueForURI(w.get(WellFormedName.Attribute.TARGET_SW));
        String t_hw = bindValueForURI(w.get(WellFormedName.Attribute.TARGET_HW));
        String oth = bindValueForURI(w.get(WellFormedName.Attribute.OTHER));
        v = pack(ed, sw_ed, t_sw, t_hw, oth);
      } else {
        // Get the value for a in w, then bind to a string
        // for inclusion in the URI.
        v = bindValueForURI(w.get(a));
      }
      // Append v to the URI then add a colon.
      uri = Utilities.strcat(uri, v, ":");
    }
    // Return the URI string, with trailing colons trimmed.
    return trim(uri);
  }

  /**
   * Top-level function used to bind WFN w to formatted string.
   * 
   * @param w
   *          WellFormedName to bind
   * @return Formatted String
   */
  public static String bindToFS(WellFormedName w) {
    // Initialize the output with the CPE v2.3 string prefix.
    String fs = "cpe:2.3:";
    for (WellFormedName.Attribute a : WellFormedName.Attribute.values()) {
      String v = bindValueForFS(w.get(a));
      fs = Utilities.strcat(fs, v);
      // add a colon except at the very end
      if (!WellFormedName.Attribute.OTHER.equals(a)) {
        fs = Utilities.strcat(fs, ":");
      }
    }
    return fs;
  }

  /**
   * Convert the value v to its proper string representation for insertion to formatted string.
   * 
   * @param v
   *          value to convert
   * @return Formatted value
   */
  private static String bindValueForFS(Object v) {
    if (v instanceof LogicalValue) {
      LogicalValue l = (LogicalValue) v;
      // The value NA binds to a blank.
      if (LogicalValue.ANY.equals(l)) {
        return "*";
      }
      // The value NA binds to a single hyphen.
      if (LogicalValue.NA.equals(l)) {
        return "-";
      }
    }
    return processQuotedChars((String) v);
  }

  /**
   * Inspect each character in string s. Certain nonalpha characters pass thru without escaping into
   * the result, but most retain escaping.
   * 
   * @param s
   * @return
   */
  private static String processQuotedChars(String s) {
    String result = "";
    int idx = 0;
    while (idx < Utilities.strlen(s)) {
      String c = Utilities.substr(s, idx, idx + 1);
      if (!c.equals("\\")) {
        // unquoted characters pass thru unharmed.
        result = Utilities.strcat(result, c);
      } else {
        // escaped characters are examined.
        String nextchr = Utilities.substr(s, idx + 1, idx + 2);
        // the period, hyphen and underscore pass unharmed.
        if (nextchr.equals(".") || nextchr.equals("-") || nextchr.equals("_")) {
          result = Utilities.strcat(result, nextchr);
          idx = idx + 2;
          continue;
        } else {
          // all others retain escaping.
          result = Utilities.strcat(result, "\\", nextchr);
          idx = idx + 2;
          continue;
        }
      }
      idx = idx + 1;
    }
    return result;
  }

  /**
   * Converts a string to the proper string for including in a CPE v2.2-conformant URI. The logical
   * value ANY binds to the blank in the 2.2-conformant URI.
   * 
   * @param s
   *          string to be converted
   * @return converted string
   */
  private static String bindValueForURI(Object s) {
    if (s instanceof LogicalValue) {
      LogicalValue l = (LogicalValue) s;
      // The value NA binds to a blank.
      if (LogicalValue.ANY.equals(l)) {
        return "";
      }
      // The value NA binds to a single hyphen.
      if (LogicalValue.NA.equals(l)) {
        return "-";
      }
    }

    // If we get here, we're dealing with a string value.
    return transformForURI((String) s);
  }

  /**
   * Scans an input string and performs the following transformations: - Pass alphanumeric characters
   * thru untouched - Percent-encode quoted non-alphanumerics as needed - Unquoted special characters
   * are mapped to their special forms
   * 
   * @param s
   *          string to be transformed
   * @return transformed string
   */
  private static String transformForURI(String s) {
    String result = "";
    int idx = 0;

    while (idx < Utilities.strlen(s)) {
      // Get the idx'th character of s.
      String thischar = Utilities.substr(s, idx, idx + 1);
      // Alphanumerics (incl. underscore) pass untouched.
      if (Utilities.isAlphanum(thischar)) {
        result = Utilities.strcat(result, thischar);
        idx = idx + 1;
        continue;
      }
      // Check for escape character.
      if (thischar.equals("\\")) {
        idx = idx + 1;
        String nxtchar = Utilities.substr(s, idx, idx + 1);
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
   * @param c
   *          the single character string to be encoded
   * @return the percent encoded string
   */
  private static String pctEncode(String c) {
    if (c.equals("!")) {
      return "%21";
    }
    if (c.equals("\"")) {
      return "%22";
    }
    if (c.equals("#")) {
      return "%23";
    }
    if (c.equals("$")) {
      return "%24";
    }
    if (c.equals("%")) {
      return "%25";
    }
    if (c.equals("&")) {
      return "%26";
    }
    if (c.equals("'")) {
      return "%27";
    }
    if (c.equals("(")) {
      return "%28";
    }
    if (c.equals(")")) {
      return "%29";
    }
    if (c.equals("*")) {
      return "%2a";
    }
    if (c.equals("+")) {
      return "%2b";
    }
    if (c.equals(",")) {
      return "%2c";
    }
    // bound without encoding.
    if (c.equals("-")) {
      return c;
    }
    // bound without encoding.
    if (c.equals(".")) {
      return c;
    }
    if (c.equals("/")) {
      return "%2f";
    }
    if (c.equals(":")) {
      return "%3a";
    }
    if (c.equals(";")) {
      return "%3b";
    }
    if (c.equals("<")) {
      return "%3c";
    }
    if (c.equals("=")) {
      return "%3d";
    }
    if (c.equals(">")) {
      return "%3e";
    }
    if (c.equals("?")) {
      return "%3f";
    }
    if (c.equals("@")) {
      return "%40";
    }
    if (c.equals("[")) {
      return "%5b";
    }
    if (c.equals("\\")) {
      return "%5c";
    }
    if (c.equals("]")) {
      return "%5d";
    }
    if (c.equals("^")) {
      return "%5e";
    }
    if (c.equals("`")) {
      return "%60";
    }
    if (c.equals("{")) {
      return "%7b";
    }
    if (c.equals("|")) {
      return "%7c";
    }
    if (c.equals("}")) {
      return "%7d";
    }
    if (c.equals("~")) {
      return "%7d";
    }
    // Shouldn't reach here, return original character
    return c;
  }

  /**
   * Packs the values of the five arguments into the single edition component. If all the values are
   * blank, the function returns a blank.
   * 
   * @param ed
   *          edition string
   * @param sw_ed
   *          software edition string
   * @param t_sw
   *          target software string
   * @param t_hw
   *          target hardware string
   * @param oth
   *          other edition information string
   * @return the packed string, or blank
   */
  private static String pack(String ed, String sw_ed, String t_sw, String t_hw, String oth) {
    if (sw_ed.equals("") && t_sw.equals("") && t_hw.equals("") && oth.equals("")) {
      // All the extended attributes are blank, so don't do
      // any packing, just return ed.
      return ed;
    }
    // Otherwise, pack the five values into a single string
    // prefixed and internally delimited with the tilde.
    return Utilities.strcat("~", ed, "~", sw_ed, "~", t_sw, "~", t_hw, "~", oth);
  }

  /**
   * Removes trailing colons from the URI.
   * 
   * @param s
   *          the string to be trimmed
   * @return the trimmed string
   */
  private static String trim(String s) {
    String s1 = Utilities.reverse(s);
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

  public static void main(String[] args) throws ParseException {
    // A few examples.
    WellFormedName wfn = new WellFormedName("a", "microsoft", "internet_explorer", "8\\.0\\.6001", "beta",
        LogicalValue.ANY, "sp2", null, null, null, null);
    WellFormedName wfn2 = new WellFormedName();
    wfn2.set(WellFormedName.Attribute.PART, "a");
    wfn2.set(WellFormedName.Attribute.VENDOR, "foo\\$bar");
    wfn2.set(WellFormedName.Attribute.PRODUCT, "insight");
    wfn2.set(WellFormedName.Attribute.VERSION, "7\\.4\\.0\\.1570");
    wfn2.set(WellFormedName.Attribute.TARGET_SW, "win2003");
    wfn2.set(WellFormedName.Attribute.UPDATE, LogicalValue.NA);
    wfn2.set(WellFormedName.Attribute.SW_EDITION, "online");
    wfn2.set(WellFormedName.Attribute.TARGET_HW, "x64");
    System.out.println(CPENameBinder.bindToURI(wfn));
    System.out.println(CPENameBinder.bindToFS(wfn2));
  }
}
