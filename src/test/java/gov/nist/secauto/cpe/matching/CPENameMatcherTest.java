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

package gov.nist.secauto.cpe.matching;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gov.nist.secauto.cpe.common.LogicalValue;
import gov.nist.secauto.cpe.common.WellFormedName;
import gov.nist.secauto.cpe.matching.CPENameMatcher;
import gov.nist.secauto.cpe.naming.CPENameUnbinder;

import org.junit.jupiter.api.Test;

import java.text.ParseException;

class CPENameMatcherTest {

  @Test
  void test() throws ParseException {
    // Examples.
    WellFormedName wfn = new WellFormedName("a", "microsoft", "internet_explorer", "8\\.0\\.6001", "beta",
        LogicalValue.ANY, "sp2", null, null, null, null);
    WellFormedName wfn2 = new WellFormedName("a", "microsoft", "internet_explorer", LogicalValue.ANY, LogicalValue.ANY,
        LogicalValue.ANY, LogicalValue.ANY, LogicalValue.ANY, LogicalValue.ANY, LogicalValue.ANY, LogicalValue.ANY);

    assertFalse(CPENameMatcher.isDisjoint(wfn, wfn2));
    assertFalse(CPENameMatcher.isEqual(wfn, wfn2));
    assertTrue(CPENameMatcher.isSubset(wfn, wfn2)); // wfn2 is a subset of wfn
    assertFalse(CPENameMatcher.isSuperset(wfn, wfn2));

    wfn = CPENameUnbinder.unbindFS("cpe:2.3:a:adobe:*:9.*:*:PalmOS:*:*:*:*:*");
    wfn2 = CPENameUnbinder.unbindURI("cpe:/a::Reader:9.3.2:-:-");
    assertTrue(CPENameMatcher.isDisjoint(wfn, wfn2)); // true, wfn2 and wfn are disjoint
    assertFalse(CPENameMatcher.isEqual(wfn, wfn2));
    assertFalse(CPENameMatcher.isSubset(wfn, wfn2));
    assertFalse(CPENameMatcher.isSuperset(wfn, wfn2));
  }

}
