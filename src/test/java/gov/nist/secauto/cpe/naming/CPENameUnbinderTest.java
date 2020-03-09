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

package gov.nist.secauto.cpe.naming;

import static org.junit.jupiter.api.Assertions.assertEquals;

import gov.nist.secauto.cpe.common.LogicalValue;
import gov.nist.secauto.cpe.common.WellFormedName;
import gov.nist.secauto.cpe.common.WellFormedName.Attribute;

import org.junit.jupiter.api.Test;

import java.text.ParseException;

class CPENameUnbinderTest {

  @Test
  void test() throws ParseException {
    // A few examples.
    WellFormedName wfn = CPENameUnbinder.unbindURI("cpe:/a:microsoft:internet_explorer%01%01%01%01:?:beta");
    assertEquals("a", wfn.get(Attribute.PART));
    assertEquals("microsoft", wfn.get(Attribute.VENDOR));
    assertEquals("internet_explorer????", wfn.get(Attribute.PRODUCT));
    assertEquals("?", wfn.get(Attribute.VERSION));
    assertEquals("beta", wfn.get(Attribute.UPDATE));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.EDITION));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.LANGUAGE));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.SW_EDITION));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.TARGET_SW));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.TARGET_HW));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.OTHER));

    wfn = CPENameUnbinder.unbindURI("cpe:/a:microsoft:internet_explorer:8.%2a:sp%3f");
    assertEquals("a", wfn.get(Attribute.PART));
    assertEquals("microsoft", wfn.get(Attribute.VENDOR));
    assertEquals("internet_explorer", wfn.get(Attribute.PRODUCT));
    assertEquals("8\\.\\*", wfn.get(Attribute.VERSION));
    assertEquals("sp\\?", wfn.get(Attribute.UPDATE));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.EDITION));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.LANGUAGE));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.SW_EDITION));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.TARGET_SW));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.TARGET_HW));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.OTHER));

    wfn = CPENameUnbinder.unbindURI("cpe:/a:microsoft:internet_explorer:8.%02:sp%01");
    assertEquals("a", wfn.get(Attribute.PART));
    assertEquals("microsoft", wfn.get(Attribute.VENDOR));
    assertEquals("internet_explorer", wfn.get(Attribute.PRODUCT));
    assertEquals("8\\.*", wfn.get(Attribute.VERSION));
    assertEquals("sp?", wfn.get(Attribute.UPDATE));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.EDITION));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.LANGUAGE));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.SW_EDITION));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.TARGET_SW));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.TARGET_HW));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.OTHER));

    wfn = CPENameUnbinder.unbindURI("cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~");
    assertEquals("a", wfn.get(Attribute.PART));
    assertEquals("hp", wfn.get(Attribute.VENDOR));
    assertEquals("insight_diagnostics", wfn.get(Attribute.PRODUCT));
    assertEquals("7\\.4\\.0\\.1570", wfn.get(Attribute.VERSION));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.UPDATE));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.EDITION));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.LANGUAGE));
    assertEquals("online", wfn.get(Attribute.SW_EDITION));
    assertEquals("win2003", wfn.get(Attribute.TARGET_SW));
    assertEquals("x64", wfn.get(Attribute.TARGET_HW));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.OTHER));

    wfn = CPENameUnbinder.unbindFS("cpe:2.3:a:micr\\?osoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*");
    assertEquals("a", wfn.get(Attribute.PART));
    assertEquals("micr\\?osoft", wfn.get(Attribute.VENDOR));
    assertEquals("internet_explorer", wfn.get(Attribute.PRODUCT));
    assertEquals("8\\.0\\.6001", wfn.get(Attribute.VERSION));
    assertEquals("beta", wfn.get(Attribute.UPDATE));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.EDITION));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.LANGUAGE));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.SW_EDITION));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.TARGET_SW));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.TARGET_HW));
    assertEquals(LogicalValue.ANY, wfn.get(Attribute.OTHER));
  }

}
