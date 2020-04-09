/*
 * Copyright 2019-2020 IDsec Solutions AB
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

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.NameID;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.certificate.CertificateAttributeMapping;
import se.idsec.signservice.integration.certificate.SigningCertificateRequirements;
import se.idsec.signservice.integration.core.error.impl.SignServiceProtocolException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.xml.JAXBContextUtils;
import se.idsec.signservice.xml.JAXBMarshaller;
import se.litsec.opensaml.saml2.attribute.AttributeBuilder;
import se.litsec.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.schemas.csig.dssext_1_1.CertRequestProperties;
import se.swedenconnect.schemas.csig.dssext_1_1.MappedAttributeType;
import se.swedenconnect.schemas.csig.dssext_1_1.PreferredSAMLAttributeNameType;
import se.swedenconnect.schemas.csig.dssext_1_1.RequestedCertAttributes;
import se.swedenconnect.schemas.saml_2_0.assertion.AttributeStatement;
import se.swedenconnect.schemas.saml_2_0.assertion.NameIDType;

/**
 * Utilities for creating DSS elements.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
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
  public static NameIDType toEntity(@Nonnull final String name) {
    NameIDType entity = new NameIDType();
    entity.setValue(name);
    entity.setFormat(NameID.ENTITY);
    return entity;
  }

  /**
   * Transforms an OpenSAML object into a JAXB object.
   * 
   * @param object
   *          the OpenSAML object
   * @param destination
   *          the class for the JAXB object
   * @return the JAXB object
   * @throws SignServiceProtocolException
   *           for protocol errors
   */
  public static <T> T toJAXB(@Nonnull final XMLObject object, @Nonnull final Class<T> destination) throws SignServiceProtocolException {
    try {
      Element element = XMLObjectSupport.marshall(object);
      JAXBContext context = JAXBContextUtils.createJAXBContext(destination);
      Object jaxb = context.createUnmarshaller().unmarshal(element);
      return destination.cast(jaxb);
    }
    catch (MarshallingException e) {
      throw new SignServiceProtocolException("Failed to marshall DSS protocol object", e);
    }
    catch (JAXBException e) {
      throw new SignServiceProtocolException("JAXB error", e);
    }
  }

  /**
   * Transforms a JAXB object to its corresponding OpenSAML object.
   * 
   * @param jaxbObject
   *          JAXB object
   * @param destination
   *          the OpenSAML class
   * @return OpenSAML object
   * @throws SignServiceProtocolException
   *           for unmarshalling errors
   */
  public static <T> T toOpenSAML(@Nonnull final Object jaxbObject, @Nonnull final Class<T> destination)
      throws SignServiceProtocolException {
    try {
      Element element = JAXBMarshaller.marshall(jaxbObject).getDocumentElement();
      Unmarshaller unmarshaller = XMLObjectSupport.getUnmarshaller(element);
      XMLObject object = unmarshaller.unmarshall(element);
      return destination.cast(object);
    }
    catch (JAXBException | UnmarshallingException e) {
      throw new SignServiceProtocolException(String.format("Failed to decode %s - %s", destination.getSimpleName(), e.getMessage()), e);
    }
  }

  /**
   * Converts a list of {@link SignerIdentityAttributeValue} objects into a {@code Signer} element.
   * 
   * @param attributes
   *          list of attributes
   * @return a ns:Signer element
   * @throws SignServiceProtocolException
   *           for encoding/decoding errors
   */
  public static AttributeStatement toAttributeStatement(@Nonnull final List<SignerIdentityAttributeValue> attributes)
      throws SignServiceProtocolException {

    org.opensaml.saml.saml2.core.AttributeStatement attributeStatement = (org.opensaml.saml.saml2.core.AttributeStatement) XMLObjectSupport
      .buildXMLObject(org.opensaml.saml.saml2.core.AttributeStatement.DEFAULT_ELEMENT_NAME);

    for (SignerIdentityAttributeValue av : attributes) {
      attributeStatement.getAttributes().add(toOpenSAMLAttribute(av));
    }
    return toJAXB(attributeStatement, AttributeStatement.class);
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

    final org.opensaml.saml.saml2.core.AttributeStatement openSaml =
        DssUtils.toOpenSAML(attributeStatement, org.opensaml.saml.saml2.core.AttributeStatement.class);

    List<SignerIdentityAttributeValue> list = new ArrayList<>();
    for (org.opensaml.saml.saml2.core.Attribute a : openSaml.getAttributes()) {
      final SignerIdentityAttributeValue attribute = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name(a.getName())
        .nameFormat(a.getNameFormat())
        .value(AttributeUtils.getAttributeStringValue(a))
        // TODO: value type ...
        .build();
      if (attribute.getValue() == null) {
        final String msg = String.format("Error getting attribute value for attribute '%s'", a.getName());
        log.error("{}: {}", CorrelationID.id(), msg);
        throw new SignServiceProtocolException(msg);
      }
      list.add(attribute);
    }

    return list;
  }

  /**
   * Converts a {@link SigningCertificateRequirements} object into a {@code CertRequestProperties} element.
   * 
   * @param certReqs
   *          signing certificate requirements
   * @param authnContextRef
   *          the level of assurance
   * @return a CertRequestProperties elements
   * @throws SignServiceProtocolException
   *           for protocol errors
   */
  public static CertRequestProperties toCertRequestProperties(final SigningCertificateRequirements certReqs,
      final String authnContextRef) throws SignServiceProtocolException {

    CertRequestProperties crp = (new se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory()).createCertRequestProperties();
    crp.setCertType(certReqs.getCertificateType().getType());
    crp.setAuthnContextClassRef(authnContextRef);

    if (certReqs.getAttributeMappings() != null) {
      RequestedCertAttributes certAttributes = new RequestedCertAttributes();
      for (CertificateAttributeMapping mapping : certReqs.getAttributeMappings()) {
        MappedAttributeType certAttr = new MappedAttributeType();
        certAttr.setCertAttributeRef(mapping.getDestination().getName());
        certAttr.setCertNameType(mapping.getDestination().getType());
        if (StringUtils.hasText(mapping.getDestination().getFriendlyName())) {
          certAttr.setFriendlyName(mapping.getDestination().getFriendlyName());
        }
        if (StringUtils.hasText(mapping.getDestination().getDefaultValue())) {
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
   * Given a {@link SignerIdentityAttributeValue} object an OpenSAML attribute is created.
   * 
   * @param attributeValue
   *          the attribute value received in the input
   * @return an OpenSAML attribute
   * @throws SignServiceProtocolException
   *           for encoding errors
   */
  public static Attribute toOpenSAMLAttribute(@Nonnull final SignerIdentityAttributeValue attributeValue)
      throws SignServiceProtocolException {
    try {
      AttributeBuilder builder = new AttributeBuilder(attributeValue.getName());
      if (!StringUtils.hasText(attributeValue.getNameFormat())) {
        builder.nameFormat(AttributeBuilder.DEFAULT_NAME_FORMAT);
      }
      String type = attributeValue.getAttributeValueType();
      if (!StringUtils.hasText(type)) {
        type = SignerIdentityAttributeValue.DEFAULT_ATTRIBUTE_VALUE_TYPE;
      }
      builder.value(getValueObject(type, attributeValue.getValue()));

      return builder.build();
    }
    catch (Exception e) {
      throw new SignServiceProtocolException("Failed to process attribute - " + e.getMessage(), e);
    }
  }

  /**
   * Based on the type an XML object is created.
   * 
   * @param type
   *          the XML type
   * @param value
   *          the value (in string representation)
   * @return the XML value
   */
  private static XMLObject getValueObject(final String type, final String value) {
    if (XSBase64Binary.TYPE_LOCAL_NAME.equalsIgnoreCase(type)) {
      XSString object = AttributeBuilder.createValueObject(XSString.TYPE_NAME, XSString.class);
      object.setValue(value);
      return object;
    }
    else if (XSBoolean.TYPE_LOCAL_NAME.equalsIgnoreCase(type)) {
      XSBoolean object = AttributeBuilder.createValueObject(XSBoolean.TYPE_NAME, XSBoolean.class);
      XSBooleanValue _value = new XSBooleanValue();
      _value.setValue(Boolean.getBoolean(value));
      object.setValue(_value);
      return object;
    }
    else if (XSInteger.TYPE_LOCAL_NAME.equalsIgnoreCase(type)) {
      XSInteger object = AttributeBuilder.createValueObject(XSInteger.TYPE_NAME, XSInteger.class);
      object.setValue(Integer.valueOf(value));
      return object;
    }
    else if (XSDateTime.TYPE_LOCAL_NAME.equalsIgnoreCase(type)) {
      XSDateTime object = AttributeBuilder.createValueObject(XSDateTime.TYPE_NAME, XSDateTime.class);
      object.setValue(DateTime.parse(value));
      return object;
    }
    else { // TODO: check if unsupported type
      // String
      XSString object = AttributeBuilder.createValueObject(XSString.TYPE_NAME, XSString.class);
      object.setValue(value);
      return object;
    }
  }

  private DssUtils() {
  }

}
