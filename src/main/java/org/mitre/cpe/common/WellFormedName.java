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

package org.mitre.cpe.common;

import java.text.ParseException;
import java.util.EnumMap;
import java.util.Map;

/**
 * The WellFormedName class represents a Well Formed Name, as defined
 * in the CPE Specification version 2.3.  
 * 
 * See {@link <a href="http://cpe.mitre.org">cpe.mitre.org</a>} for details.
 * 
 * @author <a href="mailto:jkraunelis@mitre.org">Joshua Kraunelis</a>
 * @author <a href="mailto:david.waltermire@nist.gov">David Waltermire</a>
 */
public class WellFormedName {
	public enum Attribute {
		PART,
		VENDOR,
		PRODUCT,
		VERSION,
		UPDATE,
		EDITION,
		LANGUAGE,
		SW_EDITION,
		TARGET_SW,
		TARGET_HW,
		OTHER;
	}

	// Underlying wfn representation.
    // String -> String.
    private Map<Attribute, Object> wfn = new EnumMap<Attribute, Object>(Attribute.class);

    /**
     * Constructs a new WellFormedName object, with all components set to the 
     * default value "ANY".
     */
    public WellFormedName() throws ParseException {
        for (Attribute a : Attribute.values()) {
            // don't set part to ANY
            if (!Attribute.PART.equals(a)) {
                set(a, LogicalValue.ANY);
            }
        }
    }

    /**
     * Constructs a new WellFormedName object, setting each component to the 
     * given parameter value.  If a parameter is null, the component is set to 
     * the default value "ANY".
     * @param part string representing the part component
     * @param vendor string representing the vendor component
     * @param product string representing the product component
     * @param version string representing the version component
     * @param update string representing the update component
     * @param edition string representing the edition component
     * @param language string representing the language component
     * @param sw_edition string representing the sw_edition component
     * @param target_sw string representing the target_sw component
     * @param target_hw string representing the target_hw component
     * @param other string representing the other component 
     */
    public WellFormedName(Object part, Object vendor, Object product,
            Object version, Object update, Object edition, Object language, Object sw_edition, Object target_sw, Object target_hw, Object other) throws ParseException {
        set(Attribute.PART, part);
        set(Attribute.VENDOR, vendor);
        set(Attribute.PRODUCT, product);
        set(Attribute.VERSION, version);
        set(Attribute.UPDATE, update);
        set(Attribute.EDITION, edition);
        set(Attribute.LANGUAGE, language);
        set(Attribute.SW_EDITION, sw_edition);
        set(Attribute.TARGET_SW, target_sw);
        set(Attribute.TARGET_HW, target_hw);
        set(Attribute.OTHER, other);
    }

    /** 
     * @param attribute String representing the component value to get
     * @return the String value of the given component, or default value "ANY"
     * if the component does not exist
     */
    public Object get(Attribute attribute) {
        if (this.wfn.containsKey(attribute)) {
            return this.wfn.get(attribute);
        } else {
            return LogicalValue.ANY;
        }
    }

    /** 
     * Sets the given attribute to value, if the attribute is in the list of 
     * permissible components
     * @param attribute enumerated value representing the component to set
     * @param value Object representing the value of the given component
     */
    public final void set(Attribute attribute, Object value) throws ParseException {
        // check to see if we're setting a LogicalValue ANY or NA
        if (value instanceof LogicalValue) {
            // don't allow logical values in part component
            if (Attribute.PART.equals(attribute)) {
                throw new ParseException("Error! part component cannot be a logical value", 0);
            }
        } else if (value == null || ((String) value).equals("")) {
            // if value is null or blank, set attribute to default logical ANY
        	value = LogicalValue.ANY;
        } else {
	        String svalue = (String) value;
	        // Reg exs
	        // check for printable characters - no control characters
	        if (!svalue.matches("\\p{Print}*")) {
	            throw new ParseException("Error! encountered non printable character in: " + svalue, 0);
	        }
	        // svalue has whitespace
	        if (svalue.matches(".*\\s+.*")) {
	            throw new ParseException("Error! component cannot contain whitespace: " + svalue, 0);
	        }
	        // svalue has more than one unquoted star
	        if (svalue.matches("\\*{2,}.*") || svalue.matches(".*\\*{2,}")) {
	            throw new ParseException("Error! component cannot contain more than one * in sequence: " + svalue, 0);
	        }
	        // svalue has unquoted punctuation embedded
	        if (svalue.matches(".*(?<!\\\\)[\\!\\\"\\#\\$\\%\\&\\\'\\(\\)\\+\\,\\.\\/\\:\\;\\<\\=\\>\\@\\[\\]\\^\\`\\{\\|\\}\\~\\-].*")) {
	            throw new ParseException("Error! component cannot contain unquoted punctuation: " + svalue, 0);
	        }
	        // svalue has an unquoted *
	        if (svalue.matches(".+(?<!\\\\)[\\*].+")) {
	            throw new ParseException("Error! component cannot contain embedded *: " + svalue, 0);
	        }
	        // svalue has embedded unquoted ?
	        // this will catch a single unquoted ?, so make sure we deal with that
	        //if (svalue.matches("\\?*[\\p{Graph}&&[^\\?]]*(?<!\\\\)[\\?][\\p{Graph}&&[^\\?]]*\\?*")) {
	        if (svalue.contains("?")) {
	            if (svalue.equals("?")) {
	                // single ? is valid
	            	value = svalue;
	            } else {
		            // remove leading and trailing ?s
		            StringBuffer v = new StringBuffer(svalue);
		            while (v.indexOf("?") == 0) {
		                // remove all leading ?'s
		                v.deleteCharAt(0);
		            }
		            v = v.reverse();
		            while (v.indexOf("?") == 0) {
		                // remove all trailing ?'s (string has been reversed)
		                v.deleteCharAt(0);
		            }
		            // back to normal
		            v = v.reverse();
		            // after leading and trailing ?s are removed, check if value
		            // contains unquoted ?s
		            if (v.toString().matches(".+(?<!\\\\)[\\?].+")) {
		                throw new ParseException("Error! component cannot contain embedded ?: " + svalue, 0);
		            }
	            }
	        }
	        // single asterisk is not allowed
	        if (svalue.equals("*")) {
	            throw new ParseException("Error! component cannot be a single *: " + svalue, 0);
	        }
	        // quoted hyphen not allowed by itself
	        if (svalue.equals("-")) {
	            throw new ParseException("Error! component cannot be quoted hyphen: " + svalue, 0);
	        }
	        // part must be a, o, or h
	        if (Attribute.PART.equals(attribute)) {
	            if (!svalue.equals("a") && !svalue.equals("o") && !svalue.equals("h")) {
	                throw new ParseException("Error! part component must be one of the following: 'a', 'o', 'h': " + svalue, 0);
	            }
	        }
	        value = svalue;
        }
        // should be good to go
        this.wfn.put(attribute, value);
    }

    /**
     * 
     * @return String representation of the WellFormedName
     */
    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer("wfn:[");
        for (Attribute attr : Attribute.values()) {
            sb.append(attr.name().toLowerCase());
            sb.append("=");
            Object o = wfn.get(attr);
            if (o instanceof LogicalValue) {
                sb.append(o);
                sb.append(", ");
            } else {
                sb.append("\"");
                sb.append(o);
                sb.append("\", ");
            }
        }
        sb.deleteCharAt(sb.length() - 1);
        sb.deleteCharAt(sb.length() - 1);
        sb.append("]");

        return sb.toString();
    }
}
