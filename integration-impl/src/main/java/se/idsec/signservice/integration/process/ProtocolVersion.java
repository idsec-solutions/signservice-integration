package se.idsec.signservice.integration.process;

import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * A comparable protocol version from a version string
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ProtocolVersion implements Comparable<ProtocolVersion>{

  @Getter private List<Integer> versionComponentList;
  @Getter private String versionString;

  public static ProtocolVersion getInstance(String version) {
    return new ProtocolVersion(version);
  }

  /**
   * Constructor
   *
   * @param version the version as a string of integer values separated by "."
   */
  private ProtocolVersion(String version) {
    this.versionString = version;
    versionComponentList = new ArrayList<>();
    if (StringUtils.isNotBlank(version)){
      final String[] vStringArray = version.split("\\.");
      for (String vString : vStringArray){
        versionComponentList.add(getVersionInt(vString));
      }
    }
  }

  private Integer getVersionInt(String versionComponentString) {
    try {
      return Integer.valueOf(versionComponentString);
    } catch (Exception ex) {
      throw new ClassCastException("Not a valid version");
    }
  }

  /**
   * Compares this object with the specified object for order.  Returns a
   * negative integer, zero, or a positive integer as this object is less
   * than, equal to, or greater than the specified object.
   *
   * <p>The implementor must ensure <tt>sgn(x.compareTo(y)) ==
   * -sgn(y.compareTo(x))</tt> for all <tt>x</tt> and <tt>y</tt>.  (This
   * implies that <tt>x.compareTo(y)</tt> must throw an exception iff
   * <tt>y.compareTo(x)</tt> throws an exception.)
   *
   * <p>The implementor must also ensure that the relation is transitive:
   * <tt>(x.compareTo(y)&gt;0 &amp;&amp; y.compareTo(z)&gt;0)</tt> implies
   * <tt>x.compareTo(z)&gt;0</tt>.
   *
   * <p>Finally, the implementor must ensure that <tt>x.compareTo(y)==0</tt>
   * implies that <tt>sgn(x.compareTo(z)) == sgn(y.compareTo(z))</tt>, for
   * all <tt>z</tt>.
   *
   * <p>It is strongly recommended, but <i>not</i> strictly required that
   * <tt>(x.compareTo(y)==0) == (x.equals(y))</tt>.  Generally speaking, any
   * class that implements the <tt>Comparable</tt> interface and violates
   * this condition should clearly indicate this fact.  The recommended
   * language is "Note: this class has a natural ordering that is
   * inconsistent with equals."
   *
   * <p>In the foregoing description, the notation
   * <tt>sgn(</tt><i>expression</i><tt>)</tt> designates the mathematical
   * <i>signum</i> function, which is defined to return one of <tt>-1</tt>,
   * <tt>0</tt>, or <tt>1</tt> according to whether the value of
   * <i>expression</i> is negative, zero or positive.
   *
   * @param o the object to be compared.
   * @return a negative integer, zero, or a positive integer as this object
   * is less than, equal to, or greater than the specified object.
   * @throws NullPointerException if the specified object is null
   * @throws ClassCastException   if the specified object's type prevents it
   *                              from being compared to this object.
   */
  @Override public int compareTo(ProtocolVersion o) {
    final List<Integer> compareVersionList = o.getVersionComponentList();
    // Get the number of version components
    int thisCount = versionComponentList.size();
    int compareCount = compareVersionList.size();
    // Get the number of components in the version string with the least number of components
    int minCount = thisCount < compareCount ? thisCount : compareCount;

    // Iterate through the min number of components. Starting with the most significant component
    for (int count = 0 ; count < minCount ; count ++){
      Integer thisVal = versionComponentList.get(count);
      Integer compareVal = compareVersionList.get(count);
      if (thisVal != compareVal){
        // The version component on this level does not match. Return comparison on this level
        return thisVal - compareVal;
      }
      // Version components on this level was equal. Move to next
    }
    // All components present in both version strings matched
    // In this case the version with most components is the highest version. E.g. 1.2.3 > 1.2
    return thisCount - compareCount;
  }
}
