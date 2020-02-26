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

package gov.nist.secauto.cpe.common;

import java.text.ParseException;

/**
 * A collection of utility functions for use with the gov.nist.secauto.cpe.matching and
 * gov.nist.secauto.cpe.naming packages.
 * 
 * @see <a href=
 *      "https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe/">CPE
 *      Specifications</a>
 * 
 * @author <a href="mailto:jkraunelis@mitre.org">Joshua Kraunelis</a>
 * @author <a href="mailto:david.waltermire@nist.gov">David Waltermire</a>
 */
public class Utilities {

  /**
   * Concatenates an arbitrary number of strings, in the given order.
   * 
   * @param strings
   *          strings to be concatenated
   * @return a single string representing all the arguments, concatenated
   */
  public static String strcat(String... strings) {
    StringBuilder retval = new StringBuilder();
    for (String s : strings) {
      retval.append(s);
    }
    return retval.toString();
  }

  /**
   * Extracts the characters between b and e, from the string s.
   * 
   * @param str
   *          the string which the substring should be extracted from
   * @param begin
   *          beginning index, inclusive
   * @param end
   *          ending index, exclusive
   * @return the characters between index begin and index end
   */
  public static String substr(String str, int begin, int end) {
    return str.substring(begin, end);
  }

  /**
   * Returns the number of characters in the given string.
   * 
   * @param str
   *          the string
   * @return the number of characters in the string
   */
  public static int strlen(String str) {
    return str.length();
  }

  /**
   * Searches a string for a character starting at a given offset. Returns the offset of the character
   * if found, -1 if not found.
   * 
   * @param str
   *          string to be searched
   * @param chr
   *          character to search for
   * @param offset
   *          offset to start at
   * @return the integer offset of the character, or -1
   */
  public static int strchr(String str, int chr, int offset) {
    return str.indexOf(chr, offset);
  }

  /**
   * Converts all alphabetic characters in a String to lowercase.
   * 
   * @param str
   *          string to convert to lowercase
   * @return lowercase version of str
   */
  public static String toLowercase(String str) {
    return str.toLowerCase();
  }

  /**
   * Searches a string for the first occurrence of another string, starting at a given offset.
   * 
   * @param str1
   *          String to search.
   * @param str2
   *          String to search for.
   * @param offset
   *          Integer offset or -1 if not found.
   * @return the position of the first occurrence of str2, or -1 if the string was not found
   */
  public static int indexOf(String str1, String str2, int offset) {
    return str1.indexOf(str2, offset);
  }

  /**
   * Searches string for special characters * and ?.
   * 
   * @param str
   *          String to be searched
   * @return {@code true} if string contains a wildcard, or {@code false} otherwise
   */
  public static boolean containsWildcards(String str) {
    if (str.contains("*") || str.contains("?")) {
      if (!(str.contains("\\"))) {
        return true;
      }
      return false;
    }
    return false;
  }

  /**
   * Checks if given number is even or not.
   * 
   * @param num
   *          number to check
   * @return {@code true} if number is even, {@code false} if not
   */
  public static boolean isEvenNumber(int num) {
    if (num % 2 == 0) {
      return true;
    } else {
      return false;
    }
  }

  /**
   * Counts the number of escape characters in the string beginning and ending at the given indices.
   * 
   * @param str
   *          string to search
   * @param start
   *          beginning index, inclusive
   * @param end
   *          ending index, exclusive
   * @return number of escape characters in string
   */
  public static int countEscapeCharacters(String str, int start, int end) {
    int result = 0;
    boolean active = false;
    int pos = 0;
    while (pos < end) {
      active = !active && str.charAt(pos) == '\\';
      if (active && (pos >= start)) {
        result = result + 1;
      }
      pos = pos + 1;
    }
    return result;
  }

  /**
   * Searches a string for the first unescaped colon and returns the index of that colon.
   * 
   * @param str
   *          string to search
   * @return index of first unescaped colon, or 0 if not found
   */
  public static int getUnescapedColonIndex(String str) {
    boolean found = false;
    int colonIndex = 0;
    int startIndex = 0;
    // Find the first non-escaped colon.
    while (!found) {
      colonIndex = str.indexOf(':', startIndex + 1);
      // If no colon is found, return 0.
      if (colonIndex == -1) {
        return 0;
      }
      // Peek at character before colon.
      if ((str.substring(colonIndex - 1, colonIndex)).equals("\\")) {
        // If colon is escaped, keep looking.
        startIndex = colonIndex;
      } else {
        found = true;
      }
    }
    return colonIndex;
  }

  /**
   * Determines if the string contains only alphanumeric characters or the underscore character.
   * 
   * @param str
   *          the string in question
   * @return {@code true} if c is alphanumeric or underscore, or {@code false} otherwise
   */
  public static boolean isAlphanum(String str) {
    if (str.matches("[a-zA-Z0-9]") || str.equals("_")) {
      return true;
    }
    return false;
  }

  /**
   * Returns a copy of the given string in reverse order.
   * 
   * @param str
   *          the string to be reversed
   * @return a reversed copy of s
   */
  public static String reverse(String str) {
    return new StringBuffer(str).reverse().toString();
  }

  /**
   * This function is not part of the reference implementation pseudo code found in the CPE 2.3
   * specification. It enforces two rules in the specification: 1) a CPE URI must start with the
   * characters "cpe:/". 2) A URI may not contain more than 7 components. If either rule is violated,
   * a ParseException is thrown.
   * 
   * @param str
   *          the potential CPE formatted string to validate
   * @throws ParseException
   *           if one of the rules for a CPE URI is violated
   */
  public static void validateURI(String str) throws ParseException {
    // make sure uri starts with cpe:/
    if (!str.toLowerCase().startsWith("cpe:/")) {
      throw new ParseException("Error: URI must start with 'cpe:/'.  Given: " + str, 0);
    }
    // make sure uri doesn't contain more than 7 colons
    int count = 0;
    for (int i = 0; i != str.length(); i++) {
      if (str.charAt(i) == ':') {
        count++;
      }
    }
    if (count > 7) {
      throw new ParseException("Error parsing URI.  Found " + (count - 7) + " extra components in: " + str, 0);
    }
  }

  /**
   * This function is not part of the reference implementation pseudo code found in the CPE 2.3
   * specification. It enforces three rules found in the specification: 1) A CPE formatted string must
   * start with the characters "cpe:2.3:". 2) A formatted string must contain 11 components. 3) A
   * formatted string must not contain empty components. If any rule is violated, a ParseException is
   * thrown.
   * 
   * @param str
   *          the potential CPE formatted string to validate
   * @throws ParseException
   *           if one of the rules for a CPE formatted string is violated
   */
  public static void validateFS(String str) throws ParseException {
    if (!str.toLowerCase().startsWith("cpe:2.3:")) {
      throw new ParseException("Error: Formatted String must start with \"cpe:2.3\". Given: " + str, 0);
    }
    // make sure fs contains exactly 12 unquoted colons
    int count = 0;
    for (int i = 0; i != str.length(); i++) {
      if (str.charAt(i) == ':') {
        if (str.charAt(i - 1) != '\\') {
          count++;
        }
        if ((i + 1) < str.length() && str.charAt(i + 1) == ':') {
          throw new ParseException("Error parsing formatted string.  Found empty component", 0);
        }
      }
    }
    if (count > 12) {
      int extra = (count - 12);
      StringBuffer msg = new StringBuffer("Error parsing formatted string.  Found " + extra + " extra component");
      if (extra > 1) {
        msg.append("s");
      }
      msg.append(" in: " + str);
      throw new ParseException(msg.toString(), 0);
    }
    if (count < 12) {
      int missing = (12 - count);
      StringBuffer msg = new StringBuffer("Error parsing formatted string. Missing " + missing + " component");
      if (missing > 1) {
        msg.append("s");
      }
      throw new ParseException(msg.toString(), 0);
    }
  }
}
