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

import java.text.ParseException;

/**
 * The CPENameUnBinder class is a simple implementation of the CPE Name unbinding algorithm, as
 * specified in the CPE Naming Standard version 2.3.
 * 
 * @see <a href= "https://doi.org/10.6028/NIST.IR.7695">NISTIR 7695 Section 6.1.3</a>
 * @see <a href= "https://doi.org/10.6028/NIST.IR.7695">NISTIR 7695 Section 6.2.3</a>
 * 
 * @author <a href="mailto:jkraunelis@mitre.org">Joshua Kraunelis</a>
 * @author <a href="mailto:david.waltermire@nist.gov">David Waltermire</a>
 */
public class CPENameUnbinder {

  private CPENameUnbinder() {
    // disable construction
  }

  /**
   * Top level function used to unbind a URI to a WFN.
   * 
   * @param uri
   *          String representing the URI to be unbound
   * @return WellFormedName representing the unbound URI
   * @throws ParseException if the provided uri is invalid
   */
  public static WellFormedName unbindURI(String uri) throws ParseException {
    // Validate the URI
    Utilities.validateURI(uri);
    // Initialize the empty WFN.
    WellFormedName result = new WellFormedName();

    for (int i = 0; i != 8; i++) {
      // get the i'th component of uri
      String value = getCompURI(uri, i);
      if (i > 0) {
        // Get the WFN component using the enum ordinal
        WellFormedName.Attribute attribute = WellFormedName.Attribute.values()[i - 1];

        if (WellFormedName.Attribute.EDITION.equals(attribute)) {
          // Special handling for edition component.
          // Unpack edition if needed.
          if (value.equals("") || value.equals("-") || !Utilities.substr(value, 0, 1).equals("~")) {
            // Just a logical value or a non-packed value.
            // So unbind to legacy edition, leaving other
            // extended attributes unspecified.
            result.set(attribute, decode(value));
          } else {
            // We have five values packed together here.
            unpack(value, result);
          }
        } else {
          result.set(attribute, decode(value));
        }
      }
    }
    return result;
  }

  /**
   * Top level function to unbind a formatted string to WFN.
   * 
   * @param fs
   *          Formatted string to unbind
   * @return WellFormedName representing the unbound formatted string
   * @throws ParseException
   *           if the fs argument is malformed
   */
  public static WellFormedName unbindFS(String fs) throws ParseException {
    // Validate the formatted string
    Utilities.validateFS(fs);
    // Initialize empty WFN
    WellFormedName result = new WellFormedName();
    // The cpe scheme is the 0th component, the cpe version is the 1st.
    // So we start parsing at the 2nd component.
    for (int a = 2; a != 13; a++) {
      // Get the a'th string field.
      Object value = getCompFS(fs, a);
      // Unbind the string.
      value = unbindValueFS((String) value);

      // Get the WFN component using the enum ordinal
      WellFormedName.Attribute attribute = WellFormedName.Attribute.values()[a - 2];

      // Set the value of the corresponding attribute.
      result.set(attribute, value);
    }
    return result;
  }

  /**
   * Returns the i'th field of the formatted string. The colon is the field delimiter unless prefixed
   * by a backslash.
   * 
   * @param fs
   *          formatted string to retrieve from
   * @param index
   *          index of field to retrieve from fs.
   * @return value of index of formatted string
   */
  private static String getCompFS(String fs, int index) {
    if (index == 0) {
      // return the substring from index 0 to the first occurence of an
      // unescaped colon
      int colonIndex = Utilities.getUnescapedColonIndex(fs);
      // If no colon is found, we are at the end of the formatted string,
      // so just return what's left.
      if (colonIndex == 0) {
        return fs;
      }
      return Utilities.substr(fs, 0, colonIndex);
    } else {
      return getCompFS(Utilities.substr(fs, Utilities.getUnescapedColonIndex(fs) + 1, fs.length()), index - 1);
    }
  }

  /**
   * Takes a string value and returns the appropriate logical value if string is the bound form of a
   * logical value. If string is some general value string, add quoting of non-alphanumerics as
   * needed.
   * 
   * @param value
   *          value to be unbound
   * @return logical value or quoted string
   * @throws ParseException
   *           if the s argument is malformed
   */
  private static Object unbindValueFS(String value) throws ParseException {
    if (value.equals("*")) {
      return LogicalValue.ANY;
    }
    if (value.equals("-")) {
      return LogicalValue.NA;
    }
    return addQuoting(value);
  }

  /**
   * Inspect each character in a string, copying quoted characters, with their escaping, into the
   * result. Look for unquoted non alphanumerics and if not "*" or "?", add escaping.
   * 
   * @param str
   *          the string to process
   * @return a string that has been properly escaped
   * @throws ParseException
   *           if the s argument is malformed
   */
  private static String addQuoting(String str) throws ParseException {
    String result = "";
    int idx = 0;
    boolean embedded = false;
    while (idx < Utilities.strlen(str)) {
      String ch = Utilities.substr(str, idx, idx + 1);
      if (Utilities.isAlphanum(ch) || ch.equals("_")) {
        // Alphanumeric characters pass untouched.
        result = Utilities.strcat(result, ch);
        idx = idx + 1;
        embedded = true;
        continue;
      }
      if (ch.equals("\\")) {
        // Anything quoted in the bound string stays quoted in the
        // unbound string.
        result = Utilities.strcat(result, Utilities.substr(str, idx, idx + 2));
        idx = idx + 2;
        embedded = true;
        continue;
      }
      if (ch.equals("*")) {
        // An unquoted asterisk must appear at the beginning or the end
        // of the string.
        if (idx == 0 || idx == (Utilities.strlen(str) - 1)) {
          result = Utilities.strcat(result, ch);
          idx = idx + 1;
          embedded = true;
          continue;
        } else {
          throw new ParseException("Error! cannot have unquoted * embedded in formatted string.", 0);
        }
      }
      if (ch.equals("?")) {
        // An unquoted question mark must appear at the beginning or
        // end of the string, or in a leading or trailing sequence.
        // if embedded is false, so must be preceded by ?
        // if embedded is true, so must be followed by ?
        if (((idx == 0) || (idx == (Utilities.strlen(str) - 1)))
            || (!embedded && (Utilities.substr(str, idx - 1, idx).equals("?")))
            || (embedded && (Utilities.substr(str, idx + 1, idx + 2).equals("?")))) {
          result = Utilities.strcat(result, ch);
          idx = idx + 1;
          embedded = false;
          continue;
        } else {
          throw new ParseException("Error! cannot have unquoted ? embedded in formatted string.", 0);
        }
      }
      // All other characters must be quoted.
      result = Utilities.strcat(result, "\\", ch);
      idx = idx + 1;
      embedded = true;
    }
    return result;
  }

  /**
   * Return the i'th component of the URI.
   * 
   * @param uri
   *          String representation of URI to retrieve components from
   * @param index
   *          Index of component to return
   * @return If i = 0, returns the URI scheme. Otherwise, returns the i'th component of uri
   */
  private static String getCompURI(String uri, int index) {
    if (index == 0) {
      return Utilities.substr(uri, index, uri.indexOf("/"));
    }
    String[] sa = uri.split(":");
    // If requested component exceeds the number
    // of components in URI, return blank
    if (index >= sa.length) {
      return "";
    }
    if (index == 1) {
      return Utilities.substr(sa[index], 1, sa[index].length());
    }
    return sa[index];
  }

  /**
   * Scans a string and returns a copy with all percent-encoded characters decoded. This function is
   * the inverse of pctEncode() defined in the CPENameBinder class. Only legal percent-encoded forms
   * are decoded. Others raise a ParseException.
   * 
   * @param str
   *          String to be decoded
   * @return decoded string
   * @throws ParseException
   *           if the provided string is invalid
   * @see CPENameBinder#pctEncode(java.lang.String)
   */
  private static Object decode(String str) throws ParseException {
    if (str.equals("")) {
      return LogicalValue.ANY;
    }
    if (str.equals("-")) {
      return LogicalValue.NA;
    }
    // Start the scanning loop.
    // Normalize: convert all uppercase letters to lowercase first.
    str = Utilities.toLowercase(str);
    String result = "";
    int idx = 0;
    boolean embedded = false;
    while (idx < Utilities.strlen(str)) {
      // Get the idx'th character of s.
      String ch = Utilities.substr(str, idx, idx + 1);
      // Deal with dot, hyphen, and tilde: decode with quoting.
      if (ch.equals(".") || ch.equals("-") || ch.equals("~")) {
        result = Utilities.strcat(result, "\\", ch);
        idx = idx + 1;
        // a non-%01 encountered.
        embedded = true;
        continue;
      }
      if (!ch.equals("%")) {
        result = Utilities.strcat(result, ch);
        idx = idx + 1;
        // a non-%01 encountered.
        embedded = true;
        continue;
      }
      // We get here if we have a substring starting w/ '%'.
      String form = Utilities.substr(str, idx, idx + 3);
      if (form.equals("%01")) {
        if ((idx == 0) || (idx == Utilities.strlen(str) - 3)
            || (!embedded && Utilities.substr(str, idx - 3, idx - 1).equals("%01"))
            || (embedded && (Utilities.strlen(str) >= idx + 6))
                && (Utilities.substr(str, idx + 3, idx + 6).equals("%01"))) {
          result = Utilities.strcat(result, "?");
          idx = idx + 3;
          continue;
        } else {
          throw new ParseException("Error decoding string", 0);
        }
      } else if (form.equals("%02")) {
        if ((idx == 0) || (idx == (Utilities.strlen(str) - 3))) {
          result = Utilities.strcat(result, "*");
        } else {
          throw new ParseException("Error decoding string", 0);
        }
      } else if (form.equals("%21")) {
        result = Utilities.strcat(result, "\\!");
      } else if (form.equals("%22")) {
        result = Utilities.strcat(result, "\\\"");
      } else if (form.equals("%23")) {
        result = Utilities.strcat(result, "\\#");
      } else if (form.equals("%24")) {
        result = Utilities.strcat(result, "\\$");
      } else if (form.equals("%25")) {
        result = Utilities.strcat(result, "\\%");
      } else if (form.equals("%26")) {
        result = Utilities.strcat(result, "\\&");
      } else if (form.equals("%27")) {
        result = Utilities.strcat(result, "\\'");
      } else if (form.equals("%28")) {
        result = Utilities.strcat(result, "\\(");
      } else if (form.equals("%29")) {
        result = Utilities.strcat(result, "\\)");
      } else if (form.equals("%2a")) {
        result = Utilities.strcat(result, "\\*");
      } else if (form.equals("%2b")) {
        result = Utilities.strcat(result, "\\+");
      } else if (form.equals("%2c")) {
        result = Utilities.strcat(result, "\\,");
      } else if (form.equals("%2f")) {
        result = Utilities.strcat(result, "\\/");
      } else if (form.equals("%3a")) {
        result = Utilities.strcat(result, "\\)");
      } else if (form.equals("%3b")) {
        result = Utilities.strcat(result, "\\;");
      } else if (form.equals("%3c")) {
        result = Utilities.strcat(result, "\\<");
      } else if (form.equals("%3d")) {
        result = Utilities.strcat(result, "\\=");
      } else if (form.equals("%3e")) {
        result = Utilities.strcat(result, "\\>");
      } else if (form.equals("%3f")) {
        result = Utilities.strcat(result, "\\?");
      } else if (form.equals("%40")) {
        result = Utilities.strcat(result, "\\@");
      } else if (form.equals("%5b")) {
        result = Utilities.strcat(result, "\\[");
      } else if (form.equals("%5c")) {
        result = Utilities.strcat(result, "\\\\");
      } else if (form.equals("%5d")) {
        result = Utilities.strcat(result, "\\]");
      } else if (form.equals("%5e")) {
        result = Utilities.strcat(result, "\\^");
      } else if (form.equals("%60")) {
        result = Utilities.strcat(result, "\\`");
      } else if (form.equals("%7b")) {
        result = Utilities.strcat(result, "\\{");
      } else if (form.equals("%7c")) {
        result = Utilities.strcat(result, "\\|");
      } else if (form.equals("%7d")) {
        result = Utilities.strcat(result, "\\}");
      } else if (form.equals("%7e")) {
        result = Utilities.strcat(result, "\\~");
      } else {
        throw new ParseException("Unknown form: " + form, 0);
      }
      idx = idx + 3;
      embedded = true;
    }
    return result;
  }

  /**
   * Unpacks the elements in s and sets the attributes in the given WellFormedName accordingly.
   * 
   * @param str
   *          packed String
   * @param wfn
   *          WellFormedName
   * @return The augmented WellFormedName
   * @throws ParseException
   *           if the str is marformed
   */
  private static WellFormedName unpack(String str, WellFormedName wfn) throws ParseException {
    // Parse out the five elements.
    int start = 1;
    int end = Utilities.strchr(str, '~', start);
    String edition;
    if (start == end) {
      edition = "";
    } else {
      edition = Utilities.substr(str, start, end);
    }

    start = end + 1;
    end = Utilities.strchr(str, '~', start);
    String swEdition;
    if (start == end) {
      swEdition = "";
    } else {
      swEdition = Utilities.substr(str, start, end);
    }

    start = end + 1;
    end = Utilities.strchr(str, '~', start);
    String targetSoftware;
    if (start == end) {
      targetSoftware = "";
    } else {
      targetSoftware = Utilities.substr(str, start, end);
    }

    start = end + 1;
    end = Utilities.strchr(str, '~', start);
    String targetHardware;
    if (start == end) {
      targetHardware = "";
    } else {
      targetHardware = Utilities.substr(str, start, end);
    }

    start = end + 1;
    String other;
    if (start >= Utilities.strlen(str)) {
      other = "";
    } else {
      other = Utilities.substr(str, start, Utilities.strlen(str) - 1);
    }

    // Set each component in the WFN.
    wfn.set(WellFormedName.Attribute.EDITION, decode(edition));
    wfn.set(WellFormedName.Attribute.SW_EDITION, decode(swEdition));
    wfn.set(WellFormedName.Attribute.TARGET_SW, decode(targetSoftware));
    wfn.set(WellFormedName.Attribute.TARGET_HW, decode(targetHardware));
    wfn.set(WellFormedName.Attribute.OTHER, decode(other));
    return wfn;
  }
}
