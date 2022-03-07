/*
 * Copyright 2019-2022 IDsec Solutions AB
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
package se.idsec.signservice.integration.dss;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.commons.lang.StringUtils;

import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.certificate.CertificateAttributeMapping;
import se.idsec.signservice.integration.certificate.SigningCertificateRequirements;
import se.idsec.signservice.integration.core.error.impl.SignServiceProtocolException;
import se.swedenconnect.schemas.csig.dssext_1_1.CertRequestProperties;
import se.swedenconnect.schemas.csig.dssext_1_1.MappedAttributeType;
import se.swedenconnect.schemas.csig.dssext_1_1.PreferredSAMLAttributeNameType;
import se.swedenconnect.schemas.csig.dssext_1_1.RequestedCertAttributes;
import se.swedenconnect.schemas.saml_2_0.assertion.Assertion;
import se.swedenconnect.schemas.saml_2_0.assertion.Attribute;
import se.swedenconnect.schemas.saml_2_0.assertion.AttributeStatement;
import se.swedenconnect.schemas.saml_2_0.assertion.NameIDType;

/**
 * Utilities for creating DSS elements.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DssUtils {

  /** The DSS profile we use. */
  public static final String DSS_PROFILE = "http://id.elegnamnden.se/csig/1.1/dss-ext/profile";

  /** The namespace for DSS extension. */
  public static final String DSS_EXT_NAMESPACE = "http://id.elegnamnden.se/csig/1.1/dss-ext/ns";

  /**
   * Creates a NameID object.
   *
   * @param name
   *          the name
   * @return the NameID object
   */
  public static NameIDType toEntity(final String name) {
    NameIDType entity = new NameIDType();
    entity.setValue(name);
    entity.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
    return entity;
  }

  /**
   * Given an assertion the {@code AttributeStatement} is extracted.
   *
   * @param assertion
   *          the assertion
   * @return an AttributeStatement
   */
  public static AttributeStatement getAttributeStatement(final Assertion assertion) {
    return assertion.getStatementsAndAuthnStatementsAndAuthzDecisionStatements().stream()
      .filter(AttributeStatement.class::isInstance)
      .map(AttributeStatement.class::cast)
      .findFirst()
      .orElse(null);
  }

  /**
   * Gets a String-attribute value from the given statement.
   *
   * @param statement
   *          the statement
   * @param name
   *          the attribute name
   * @return the value or null if no value is found
   */
  public static String getAttributeValue(final AttributeStatement statement, final String name) {
    return getAttributeValue(statement, name, String.class);
  }

  /**
   * Gets an attribute value from the given statement having the given type.
   *
   * @param statement
   *          the statement
   * @param name
   *          the attribute name
   * @param type
   *          the type of the attribute value
   * @return the value or null if no value is found
   */
  public static <T> T getAttributeValue(final AttributeStatement statement, final String name, final Class<T> type) {
    return statement.getAttributesAndEncryptedAttributes().stream()
      .filter(Attribute.class::isInstance)
      .map(Attribute.class::cast)
      .filter(a -> Objects.equals(a.getName(), name))
      .filter(Attribute::isSetAttributeValues)
      .map(a -> a.getAttributeValues().get(0))
      .filter(type::isInstance)
      .map(type::cast)
      .findFirst()
      .orElse(null);
  }

  /**
   * Converts a list of {@link SignerIdentityAttributeValue} objects into a {@code AttributeStatement} element.
   *
   * @param attributes
   *          list of attributes
   * @return an AttributeStatement element
   * @throws SignServiceProtocolException
   *           for encoding/decoding errors
   */
  public static AttributeStatement toAttributeStatement(@Nonnull final List<SignerIdentityAttributeValue> attributes)
      throws SignServiceProtocolException {

    final AttributeStatement attributeStatement = new AttributeStatement();
    for (final SignerIdentityAttributeValue siav : attributes) {

      final Attribute attribute = toAttribute(siav);

      // We want to handle multi-valued attributes in both directions ...
      final Attribute existing = attributeStatement.getAttributesAndEncryptedAttributes().stream()
        .filter(Attribute.class::isInstance)
        .map(Attribute.class::cast)
        .filter(a -> Objects.equals(a.getName(), siav.getName()))
        .findFirst()
        .orElse(null);

      if (existing != null) {
        existing.getAttributeValues().add(attribute.getAttributeValues().get(0));
      }
      else {
        attributeStatement.getAttributesAndEncryptedAttributes().add(attribute);
      }
    }

    return attributeStatement;
  }

  /**
   * Converts from an {@code AttributeStatement} object to a list of {@code SignerIdentityAttributeValue} objects.
   *
   * @param attributeStatement
   *          the statement to convert
   * @return a list of SignerIdentityAttributeValue objects
   * @throws SignServiceProtocolException
   *           for unmarshalling errors
   */
  public static List<SignerIdentityAttributeValue> fromAttributeStatement(@Nonnull final AttributeStatement attributeStatement)
      throws SignServiceProtocolException {

    final List<SignerIdentityAttributeValue> list = new ArrayList<>();

    attributeStatement.getAttributesAndEncryptedAttributes().stream()
      .filter(Attribute.class::isInstance)
      .map(Attribute.class::cast)
      .map(a -> toSignerIdentityAttributeValue(a))
      .forEach(av -> list.addAll(av));

    return list;
  }

  /**
   * Converts a {@link SigningCertificateRequirements} object into a {@code CertRequestProperties} element.
   *
   * @param certReqs
   *          signing certificate requirements
   * @param authnContextClassRefs
   *          the level of assurance(s)
   * @return a CertRequestProperties elements
   * @throws SignServiceProtocolException
   *           for protocol errors
   */
  public static CertRequestProperties toCertRequestProperties(final SigningCertificateRequirements certReqs,
      final List<String> authnContextClassRefs) throws SignServiceProtocolException {

    CertRequestProperties crp = (new se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory()).createCertRequestProperties();
    crp.setCertType(certReqs.getCertificateType().getType());
    crp.getAuthnContextClassRefs().addAll(authnContextClassRefs);

    if (certReqs.getAttributeMappings() != null) {
      RequestedCertAttributes certAttributes = new RequestedCertAttributes();
      for (CertificateAttributeMapping mapping : certReqs.getAttributeMappings()) {
        MappedAttributeType certAttr = new MappedAttributeType();
        certAttr.setCertAttributeRef(mapping.getDestination().getName());
        certAttr.setCertNameType(mapping.getDestination().getType());
        if (StringUtils.isNotBlank(mapping.getDestination().getFriendlyName())) {
          certAttr.setFriendlyName(mapping.getDestination().getFriendlyName());
        }
        if (StringUtils.isNotBlank(mapping.getDestination().getDefaultValue())) {
          certAttr.setDefaultValue(mapping.getDestination().getDefaultValue());
        }
        certAttr.setRequired(mapping.getDestination().getRequired() != null
            ? mapping.getDestination().getRequired().booleanValue()
            : false);

        if (mapping.getSources() != null) {
          int order = 0;
          for (SignerIdentityAttribute sia : mapping.getSources()) {
            PreferredSAMLAttributeNameType samlAttribute = new PreferredSAMLAttributeNameType();
            if (mapping.getSources().size() > 1) {
              samlAttribute.setOrder(order++);
            }
            samlAttribute.setValue(sia.getName());
            certAttr.getSamlAttributeNames().add(samlAttribute);
          }
        }
        certAttributes.getRequestedCertAttributes().add(certAttr);
      }
      crp.setRequestedCertAttributes(certAttributes);
    }

    return crp;
  }

  /**
   * Creates a SAML {@link Attribute} given a {@link SignerIdentityAttributeValue}.
   *
   * @param value
   *          the value to transform into an Attribute
   * @return an Attribute
   * @throws SignServiceProtocolException
   *           for protocol errors
   */
  public static Attribute toAttribute(final SignerIdentityAttributeValue value) throws SignServiceProtocolException {
    if (value.getType() != null && !SignerIdentityAttribute.SAML_TYPE.equalsIgnoreCase(value.getType())) {
      throw new SignServiceProtocolException(
        String.format("Unsupported attribute type '%s' - Only '%s' is supported",
          value.getType(), SignerIdentityAttribute.SAML_TYPE));
    }
    final Attribute attribute = new Attribute();
    attribute.setName(value.getName());
    attribute.setNameFormat(value.getNameFormat());
    attribute.getAttributeValues().add(toAttributeValue(value));
    return attribute;
  }

  /**
   * Given a {@link SignerIdentityAttributeValue} the method extracts its value and converts it to the correct type.
   *
   * @param siav
   *          the object to convert
   * @return the attribute value
   * @throws SignServiceProtocolException
   *           for non supported values
   */
  public static Object toAttributeValue(final SignerIdentityAttributeValue siav) throws SignServiceProtocolException {
    try {
      if (siav.getAttributeValueType() == null
          || SignerIdentityAttributeValue.DEFAULT_ATTRIBUTE_VALUE_TYPE.equals(siav.getAttributeValueType())) {
        return siav.getValue();
      }
      else if ("integer".equals(siav.getAttributeValueType())) {
        return new BigInteger(siav.getValue());
      }
      else if ("boolean".equals(siav.getAttributeValueType())) {
        if ("1".equals(siav.getValue())) {
          return Boolean.TRUE;
        }
        else if ("0".equals(siav.getAttributeValueType())) {
          return Boolean.FALSE;
        }
        else {
          return Boolean.parseBoolean(siav.getValue());
        }
      }
      else if ("dateTime".equalsIgnoreCase(siav.getAttributeValueType())
          || "date".equalsIgnoreCase(siav.getAttributeValueType())) {
        return DatatypeFactory.newInstance().newXMLGregorianCalendar(siav.getValue());
      }
      else {
        throw new SignServiceProtocolException(String.format("Attribute '%s' has type '%s' - Not supported",
          siav.getName(), siav.getAttributeValueType()));
      }
    }
    catch (final IllegalArgumentException | DatatypeConfigurationException e) {
      throw new SignServiceProtocolException(String.format("Attribute '%s' has type '%s' - could not parse value",
        siav.getName(), siav.getAttributeValueType()), e);
    }
  }

  /**
   * Given an attribute, the method transforms it into a {@link SignerIdentityAttributeValue}.
   * <p>
   * Note: If the attribute is multi-valued, several {@link SignerIdentityAttributeValue} instances will be created.
   * </p>
   *
   * @param attribute
   *          the attribute to convert
   * @return a list of SignerIdentityAttributeValue objects
   */
  public static List<SignerIdentityAttributeValue> toSignerIdentityAttributeValue(final Attribute attribute) {
    List<SignerIdentityAttributeValue> result = new ArrayList<>();
    for (final Object v : attribute.getAttributeValues()) {
      final SignerIdentityAttributeValue siav = new SignerIdentityAttributeValue();
      siav.setType(SignerIdentityAttribute.SAML_TYPE);
      siav.setName(attribute.getName());
      siav.setNameFormat(attribute.getNameFormat());
      if (String.class.isInstance(v)) {
        siav.setAttributeValueType("string");
        siav.setValue(String.class.cast(v));
      }
      else if (Boolean.class.isInstance(v)) {
        siav.setAttributeValueType("boolean");
        siav.setValue(Boolean.class.cast(v).toString());
      }
      else if (BigInteger.class.isInstance(v)) {
        siav.setAttributeValueType("integer");
        siav.setValue(BigInteger.class.cast(v).toString());
      }
      else if (XMLGregorianCalendar.class.isInstance(v)) {
        final XMLGregorianCalendar t = XMLGregorianCalendar.class.cast(v);
        siav.setAttributeValueType(t.getXMLSchemaType().getLocalPart());
        siav.setValue(t.toXMLFormat());
      }
      else {
        // Hmm ...
        siav.setValue(v.toString());
      }
      result.add(siav);
    }
    return result;
  }

  private DssUtils() {
  }

}
