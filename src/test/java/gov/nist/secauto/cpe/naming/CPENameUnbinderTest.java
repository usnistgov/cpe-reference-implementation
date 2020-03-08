
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
