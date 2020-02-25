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

package org.mitre.cpe.matching;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.mitre.cpe.common.LogicalValue;
import org.mitre.cpe.common.Utilities;
import org.mitre.cpe.common.WellFormedName;
import org.mitre.cpe.common.WellFormedName.Attribute;
import org.mitre.cpe.naming.CPENameUnbinder;

/**
 * The CPENameMatcher is an implementation of the CPE Matching algorithm, 
 * as specified in the CPE Matching Standard version 2.3.  
 * 
 * See {@link <a href="http://cpe.mitre.org">cpe.mitre.org</a>} for more information.
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
     * @param source Source WFN
     * @param target Target WFN
     * @return true if the names are disjoint, false otherwise
     */
    public static boolean isDisjoint(WellFormedName source, WellFormedName target) {
        // if any pairwise comparison is disjoint, the names are disjoint.
    	Map<WellFormedName.Attribute, Relation> result_list = compareWFNs(source, target);
        for (Relation result : result_list.values()) {
            if (Relation.DISJOINT.equals(result)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Tests two Well Formed Names for equality. 
     * @param source Source WFN
     * @param target Target WFN
     * @return true if the names are equal, false otherwise
     */
    public static boolean isEqual(WellFormedName source, WellFormedName target) {
        // if every pairwise comparison is equal, the names are equal.
    	Map<WellFormedName.Attribute, Relation> result_list = compareWFNs(source, target);
        for (Relation result : result_list.values()) {
            if (!(Relation.EQUAL.equals(result))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Tests if the target Well Formed Name is a subset of the source Well Formed
     * Name.  
     * @param source Source WFN
     * @param target Target WFN
     * @return true if the target is a subset of the source, false otherwise
     */
    public static boolean isSubset(WellFormedName source, WellFormedName target) {
        // if any comparison is anything other than subset or equal, then target is
        // not a subset of source.
    	Map<WellFormedName.Attribute, Relation> result_list = compareWFNs(source, target);
        for (Relation result : result_list.values()) {
            if (!(Relation.SUBSET.equals(result)) && !(Relation.EQUAL.equals(result))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Tests if the target Well Formed name is a superset of the source Well Formed
     * Name.
     * @param source Source WFN
     * @param target Target WFN
     * @return true if the target is a superset of the source, false otherwise
     */
    public static boolean isSuperset(WellFormedName source, WellFormedName target) {
        // if any comparison is anything other than superset or equal, then target is not
        // a superset of source.
    	Map<WellFormedName.Attribute, Relation> result_list = compareWFNs(source, target);
        for (Relation result : result_list.values()) {
            if ((!Relation.SUPERSET.equals(result)) && (!Relation.EQUAL.equals(result))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Compares each attribute value pair in two Well Formed Names.
     * @param source Source WFN
     * @param target Target WFN
     * @return A Hashtable mapping attribute string to attribute value Relation
     */
    public static Map<WellFormedName.Attribute, Relation> compareWFNs(WellFormedName source, WellFormedName target) {
        Map<WellFormedName.Attribute, Relation> result = new LinkedHashMap<WellFormedName.Attribute, Relation>(Attribute.values().length);
        for (WellFormedName.Attribute attribute : Attribute.values()) {
            result.put(attribute, compare(source.get(attribute), target.get(attribute)));
        }
        return result;
    }

    /**
     * Compares an attribute value pair.
     * @param source Source attribute value.
     * @param target Target attribute value.
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
        if (lvSource != null && lvTarget != null) {
            // If Logical Values are equal, result is equal.
            if (lvSource.equals(lvTarget)) {
                return Relation.EQUAL;
            }
        }
        // If source value is ANY, result is a superset.
        if (lvSource != null) {
            if (LogicalValue.ANY.equals(lvSource)) {
                return Relation.SUPERSET;
            }
        }
        // If target value is ANY, result is a subset.
        if (lvTarget != null) {
            if (LogicalValue.ANY.equals(lvTarget)) {
                return Relation.SUBSET;
            }
        }
        // If source or target is NA, result is disjoint.
        if (lvSource != null) {
            if (LogicalValue.NA.equals(lvSource)) {
                return Relation.DISJOINT;
            }
        }
        if (lvTarget != null) {
            if (LogicalValue.NA.equals(lvTarget)) {
                return Relation.DISJOINT;
            }
        }
        // only Strings will get to this point, not LogicalValues
        return compareStrings((String) source, (String) target);
    }

    /**
     * Compares a source string to a target string, and addresses the condition 
     * in which the source string includes unquoted special characters. It 
     * performs a simple regular expression  match, with the assumption that 
     * (as required) unquoted special characters appear only at the beginning 
     * and/or the end of the source string. It also properly differentiates 
     * between unquoted and quoted special characters.
     * 
     * @return Relation between source and target Strings.
     */
    private static Relation compareStrings(String source, String target) {
        int start = 0;
        int end = Utilities.strlen(source);
        int begins = 0;
        int ends = 0;
        int index, leftover, escapes;

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
        index = -1;
        leftover = Utilities.strlen(target);
        while (leftover > 0) {
            index = Utilities.indexOf(target, source, index + 1);
            if (index == -1) {
                break;
            }
            escapes = Utilities.countEscapeCharacters(target, 0, index);
            if ((index > 0) && (begins != -1) && (begins < (index - escapes))) {
                break;
            }
            escapes = Utilities.countEscapeCharacters(target, index + 1, Utilities.strlen(target));
            leftover = Utilities.strlen(target) - index - escapes - Utilities.strlen(source);
            if ((leftover > 0) && ((ends != -1) && (leftover > ends))) {
                continue;
            }
            return Relation.SUPERSET;
        }
        return Relation.DISJOINT;
    }

    /**
     * Searches a string for the backslash character
     * @param str string to search in
     * @param idx end index
     * @return true if the number of backslash characters is even, false if odd
     */
    private static boolean isEvenWildcards(String str, int idx) {
        int result = 0;
        while ((idx > 0) && (Utilities.strchr(str, "\\", idx - 1)) != -1) {
            idx = idx - 1;
            result = result + 1;
        }
        return Utilities.isEvenNumber(result);
    }

    /**
     * Tests if an Object is an instance of the String class
     * @param arg the Object to test
     * @return true if arg is a String, false if not
     */
    private static boolean isString(Object arg) {
        if (arg instanceof String) {
            return true;
        } else {
            return false;
        }
    }

    public static void main(String[] args) throws ParseException {
        // Examples.
        WellFormedName wfn = new WellFormedName("a", "microsoft", "internet_explorer", "8\\.0\\.6001", "beta", LogicalValue.ANY, "sp2", null, null, null, null);
        WellFormedName wfn2 = new WellFormedName("a", "microsoft", "internet_explorer", LogicalValue.ANY, LogicalValue.ANY, LogicalValue.ANY, LogicalValue.ANY, LogicalValue.ANY, LogicalValue.ANY, LogicalValue.ANY, LogicalValue.ANY);
        System.out.println(CPENameMatcher.isDisjoint(wfn, wfn2)); // false
        System.out.println(CPENameMatcher.isEqual(wfn, wfn2)); // false
        System.out.println(CPENameMatcher.isSubset(wfn, wfn2)); // true, wfn2 is a subset of wfn
        System.out.println(CPENameMatcher.isSuperset(wfn, wfn2)); // false
        wfn = CPENameUnbinder.unbindFS("cpe:2.3:a:adobe:*:9.*:*:PalmOS:*:*:*:*:*");
        wfn2 = CPENameUnbinder.unbindURI("cpe:/a::Reader:9.3.2:-:-");
        System.out.println(CPENameMatcher.isDisjoint(wfn, wfn2)); // true, wfn2 and wfn are disjoint
        System.out.println(CPENameMatcher.isEqual(wfn, wfn2)); // false 
        System.out.println(CPENameMatcher.isSubset(wfn, wfn2)); // false
        System.out.println(CPENameMatcher.isSuperset(wfn, wfn2)); // false
    }
}
