package se.idsec.signservice.integration.process.impl;

import org.junit.Assert;
import org.junit.Test;
import se.idsec.signservice.integration.process.ProtocolVersion;
import se.idsec.signservice.integration.testbase.TestBase;

/**
 * Testing the protocol version comparator
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ProtocolComparatorTest extends TestBase {

  @Test
  public void testVersionComparator() {

    Assert.assertEquals(0, compare("1", "1"));
    Assert.assertEquals(0, compare("", ""));
    Assert.assertEquals(0, compare("1.2", "1.2"));
    Assert.assertEquals(0, compare("1.13.2", "1.13.2"));
    Assert.assertEquals(0, compare("1.2.3.4.5.6.7.8", "1.2.3.4.5.6.7.8"));
    Assert.assertTrue(compare("1.15", "1.5") > 0);
    Assert.assertTrue(compare("1.5.1.11", "1.5.1.9") > 0);
    Assert.assertTrue(compare("1.5.1", "1.5") > 0);
    Assert.assertTrue(compare("2.5", "1.15") > 0);
  }

  @Test(expected = ClassCastException.class)
  public void testIllegalVersionStringComponent() {
    ProtocolVersion.getInstance("1.sdfsdfsdf");
  }

  @Test(expected = ClassCastException.class)
  public void testIllegalVersionJustString() {
    ProtocolVersion.getInstance("not a number");
  }

  private int compare(String version, String otherVersion) {
    return ProtocolVersion.getInstance(version).compareTo(ProtocolVersion.getInstance(otherVersion));
  }

}
