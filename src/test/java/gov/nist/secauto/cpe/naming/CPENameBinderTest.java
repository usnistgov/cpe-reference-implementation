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

import org.junit.jupiter.api.Test;

import java.text.ParseException;

class CPENameBinderTest {

  @Test
  void test() throws ParseException {
    // A few examples.
    WellFormedName wfn = new WellFormedName("a", "microsoft", "internet_explorer", "8\\.0\\.6001", "beta",
        LogicalValue.ANY, "sp2", null, null, null, null);
    assertEquals("cpe:/a:microsoft:internet_explorer:8.0.6001:beta::sp2", CPENameBinder.bindToURI(wfn));

    WellFormedName wfn2 = new WellFormedName();
    wfn2.set(WellFormedName.Attribute.PART, "a");
    wfn2.set(WellFormedName.Attribute.VENDOR, "foo\\$bar");
    wfn2.set(WellFormedName.Attribute.PRODUCT, "insight");
    wfn2.set(WellFormedName.Attribute.VERSION, "7\\.4\\.0\\.1570");
    wfn2.set(WellFormedName.Attribute.TARGET_SW, "win2003");
    wfn2.set(WellFormedName.Attribute.UPDATE, LogicalValue.NA);
    wfn2.set(WellFormedName.Attribute.SW_EDITION, "online");
    wfn2.set(WellFormedName.Attribute.TARGET_HW, "x64");
    assertEquals("cpe:2.3:a:foo\\$bar:insight:7.4.0.1570:-:*:*:online:win2003:x64:*", CPENameBinder.bindToFS(wfn2));
  }

}
