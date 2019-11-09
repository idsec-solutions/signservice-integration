/*
 * Copyright 2019 IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.idsec.signservice.integration.attributes;

/**
 * A specialization of the {@link IdentityAttribute} interface used to represents attributes in X.509 certificates.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CertificateIdentityAttribute extends IdentityAttribute {

  /**
   * The type of a certificate identity attribute.
   */
  public enum Type {
    /** The attribute is an X.509 attribute placed in the Relative Distinguished Name. */
    RDN("rdn"),
    /** The attribute is an X.509 attribute placed in Subject Alternative Name extension. */
    SAN("san");

    /**
     * Gets the textual representation of the type.
     * 
     * @return the type
     */
    public String getType() {
      return this.type;
    }

    /**
     * Given the textual representation the method returns the enum type
     * 
     * @param type
     *          the type
     * @return the enum type
     */
    public static Type fromType(String type) {
      for (Type t : Type.values()) {
        if (t.getType().equalsIgnoreCase(type)) {
          return t;
        }
      }
      return null;
    }

    private String type;

    private Type(String type) {
      this.type = type;
    }
  }

}
