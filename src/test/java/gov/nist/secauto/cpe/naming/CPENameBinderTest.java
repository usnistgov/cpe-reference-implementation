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
