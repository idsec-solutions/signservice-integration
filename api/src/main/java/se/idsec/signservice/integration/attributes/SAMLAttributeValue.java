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
 * Representation of a SAML attribute value.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SAMLAttributeValue implements IdentityAttributeValue {

  /** The default name format to use. */
  public static final String DEFAULT_NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

  /** The default XSI type for the attribute value. */
  public static final String DEFAULT_XSI_TYPE = "string";

  /** The SAML attribute name. */
  private String name;

  /** The SAML attribute value (in its string representation). */
  private String value;

  /** The SAML name format. */
  private String nameFormat;

  /** The XSI type (without the namespace prefix). */
  private String xsiType;

  /**
   * Default constructor.
   */
  public SAMLAttributeValue() {
  }

  /**
   * Constructor assigning a string valued attribute.
   * 
   * @param name
   *          the attribute name
   * @param value
   *          the attribute name
   */
  public SAMLAttributeValue(String name, String value) {
    this.name = name;
    this.value = value;
  }

  /**
   * Constructor assigning all parameters of a SAML attribute.
   * 
   * @param name
   *          the attribute name
   * @param value
   *          the attribute name
   * @param nameFormat
   *          the name format
   * @param xsiType
   *          the XSI type (without the namespace prefix)
   */
  public SAMLAttributeValue(String name, String value, String nameFormat, String xsiType) {
    this.name = name;
    this.value = value;
    this.nameFormat = nameFormat;
    this.xsiType = xsiType;
  }

  /**
   * Returns "SAML".
   */
  @Override
  public String getType() {
    return "SAML";
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return this.name;
  }

  /**
   * Assigns the SAML attribute name.
   * 
   * @param name
   *          the attribute name
   */
  public void setName(String name) {
    this.name = name;
  }

  /** {@inheritDoc} */
  @Override
  public String getValue() {
    return this.value;
  }

  /**
   * Assigns the attribute value (in its string representation).
   * 
   * @param value
   *          the attibute value
   */
  public void setValue(String value) {
    this.value = value;
  }

  /**
   * Returns the name format.
   * <p>
   * If not explicitly assigned, {@value #DEFAULT_NAME_FORMAT} is returned.
   * </p>
   * 
   * @return the name format for the attribute value
   */
  public String getNameFormat() {
    return this.nameFormat != null ? this.nameFormat : DEFAULT_NAME_FORMAT;
  }

  /**
   * Assigns the name format to use.
   * <p>
   * If not explicitly assigned, {@value #DEFAULT_NAME_FORMAT} will be assumed.
   * </p>
   * 
   * @param nameFormat
   *          the name format URI
   */
  public void setNameFormat(String nameFormat) {
    this.nameFormat = nameFormat;
  }

  /**
   * Gets the XSI type of the attribute value.
   * <p>
   * If not explicitly assigned, {@value #DEFAULT_XSI_TYPE} is returned.
   * </p>
   * 
   * @return the XSI type (without the namespace prefix)
   */
  public String getXsiType() {
    return this.xsiType != null ? this.xsiType : DEFAULT_XSI_TYPE;
  }

  /**
   * Assigns the XSI type for the attribute value.
   * <p>
   * If not explicitly assigned, {@value #DEFAULT_XSI_TYPE} is assumed.
   * </p>
   * 
   * @param xsiType
   *          the XSI type (without the namespace prefix)
   */
  public void setXsiType(String xsiType) {
    this.xsiType = xsiType;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "SAMLAttributeValue [name='" + this.name + "',value='" + this.value + "',nameFormat='" + nameFormat + "',xsiType='"
        + this.xsiType + "']";
  }

  // TODO: Add builder
  
}
