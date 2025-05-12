/*
 * Copyright 2019-2025 IDsec Solutions AB
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.core.error.impl.SignServiceProtocolException;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.schemas.saml_2_0.assertion.Assertion;
import se.swedenconnect.schemas.saml_2_0.assertion.Attribute;
import se.swedenconnect.schemas.saml_2_0.assertion.AttributeStatement;
import se.swedenconnect.schemas.saml_2_0.assertion.NameIDType;
import se.swedenconnect.xml.jaxb.JAXBUnmarshaller;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Test cases for DssUtils.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DssUtilsTest {

  private final Assertion assertion;

  public DssUtilsTest() throws Exception {
    try (final InputStream is = DssUtilsTest.class.getClassLoader().getResourceAsStream("assertion.xml")) {
      final Document doc = DOMUtils.inputStreamToDocument(is);
      this.assertion = JAXBUnmarshaller.unmarshall(doc, Assertion.class);
    }
  }

  @Test
  public void testEntity() {
    final NameIDType entity = DssUtils.toEntity("https://kalle.kula.se");
    Assertions.assertNotNull(entity);
    Assertions.assertEquals("https://kalle.kula.se", entity.getValue());
  }

  @Test
  public void testGetAttributeStatement() {
    final AttributeStatement statement = DssUtils.getAttributeStatement(this.assertion);
    Assertions.assertNotNull(statement);
  }

  @Test
  public void testGetStringAttributeValue() {
    final AttributeStatement statement = DssUtils.getAttributeStatement(this.assertion);
    final String value = DssUtils.getAttributeValue(statement, "urn:oid:1.2.752.29.4.13");
    Assertions.assertNotNull(value);
    Assertions.assertEquals("195207306886", value);

    // The same, but not type info for the attribute value ...
    final String value2 = DssUtils.getAttributeValue(statement, "urn:oid:0.9.2342.19200300.100.1.3");
    Assertions.assertNotNull(value2);
    Assertions.assertEquals("john.doe@example.com", value2);

    // Not a string
    Assertions.assertNull(DssUtils.getAttributeValue(statement, "urn:oid:2.16.840.1.113730.3.1.241"));

    // Not present
    Assertions.assertNull(DssUtils.getAttributeValue(statement, "urn:oid:1.2.3.4.5"));
  }

  @Test
  public void testGetAttributeValue() throws Exception {
    final AttributeStatement statement = DssUtils.getAttributeStatement(this.assertion);
    final String value = DssUtils.getAttributeValue(statement, "urn:oid:1.2.752.29.4.13", String.class);
    Assertions.assertNotNull(value);
    Assertions.assertEquals("195207306886", value);

    final XMLGregorianCalendar dateTime =
        DssUtils.getAttributeValue(statement, "urn:oid:2.16.840.1.113730.3.1.241", XMLGregorianCalendar.class);
    Assertions.assertNotNull(dateTime);
    Assertions.assertEquals(DatatypeFactory.newInstance().newXMLGregorianCalendar("2002-05-30T09:00:00"), dateTime);

    // Not present
    Assertions.assertNull(DssUtils.getAttributeValue(statement, "urn:oid:1.2.3.4.5", String.class));
  }

  @Test
  void testNpeFixInToSignerIdentityAttributeValue() throws Exception {
    final Assertion testAssertion;
    try (final InputStream is = DssUtilsTest.class.getClassLoader().getResourceAsStream("IS-75-saml-assertion.xml")) {
      final Document doc = DOMUtils.inputStreamToDocument(is);
      testAssertion = JAXBUnmarshaller.unmarshall(doc, Assertion.class);
    }
    final AttributeStatement attributeStatement = DssUtils.getAttributeStatement(testAssertion);

    final String value = DssUtils.getAttributeValue(attributeStatement, "urn:oid:1.3.6.1.4.1.5923.1.1.1.10");
    Assertions.assertNotNull(value);
    Assertions.assertEquals("IKXQZCJJPR7WF3L7TV7NVQV4MZO4F26M", value);

    final Attribute attr = attributeStatement.getAttributesAndEncryptedAttributes().stream()
        .filter(Attribute.class::isInstance)
        .map(Attribute.class::cast)
        .filter(a -> Objects.equals(a.getName(), "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"))
        .filter(Attribute::isSetAttributeValues)
        .findFirst()
        .orElse(null);
    final List<SignerIdentityAttributeValue> siav = DssUtils.toSignerIdentityAttributeValue(attr);
    Assertions.assertNotNull(siav);
    Assertions.assertEquals(1, siav.size());
    Assertions.assertEquals("IKXQZCJJPR7WF3L7TV7NVQV4MZO4F26M", siav.get(0).getValue());

    final List<SignerIdentityAttributeValue> values = DssUtils.fromAttributeStatement(attributeStatement);
    Assertions.assertNotNull(values);
    Assertions.assertEquals(8, values.size());
  }

  @Test
  public void testToAttributeStatement() throws SignServiceProtocolException {
    final List<SignerIdentityAttributeValue> list = Arrays.asList(
        SignerIdentityAttributeValue.builder()
            .type(SignerIdentityAttribute.SAML_TYPE)
            .name("urn:oid:1.2.752.29.4.13")
            .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
            .value("195207306886")
            .attributeValueType("string")
            .build(),
        SignerIdentityAttributeValue.builder()
            .name("urn:oid:1.2.3.4.5")
            .value("value")
            .build());

    final AttributeStatement statement = DssUtils.toAttributeStatement(list);
    Assertions.assertNotNull(statement);
    Assertions.assertTrue(statement.getAttributesAndEncryptedAttributes().size() == 2);
    Assertions.assertEquals("195207306886", DssUtils.getAttributeValue(statement, "urn:oid:1.2.752.29.4.13"));
    Assertions.assertEquals("value", DssUtils.getAttributeValue(statement, "urn:oid:1.2.3.4.5"));

    // Test multivalued ...
    final List<SignerIdentityAttributeValue> list2 = Arrays.asList(
        SignerIdentityAttributeValue.builder()
            .type(SignerIdentityAttribute.SAML_TYPE)
            .name("urn:oid:1.2.752.29.4.13")
            .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
            .value("195207306886")
            .attributeValueType("string")
            .build(),
        SignerIdentityAttributeValue.builder()
            .type(SignerIdentityAttribute.SAML_TYPE)
            .name("urn:oid:1.2.752.29.4.13")
            .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
            .value("196911292032")
            .attributeValueType("string")
            .build());

    final AttributeStatement statement2 = DssUtils.toAttributeStatement(list2);
    Assertions.assertNotNull(statement2);
    Assertions.assertTrue(statement2.getAttributesAndEncryptedAttributes().size() == 1);
    Assertions.assertTrue(
        ((Attribute) statement2.getAttributesAndEncryptedAttributes().get(0)).getAttributeValues().size() == 2);
  }

  @Test
  public void testFromAttributeStatement() {
    final AttributeStatement statement = DssUtils.getAttributeStatement(this.assertion);
    final List<SignerIdentityAttributeValue> result = DssUtils.fromAttributeStatement(statement);
    Assertions.assertEquals(6, result.size());
  }

  @Test
  public void testToAttribute() throws Exception {
    final SignerIdentityAttributeValue value = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.752.29.4.13")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("195207306886")
        .attributeValueType("string")
        .build();

    final Attribute attribute = DssUtils.toAttribute(value);
    Assertions.assertNotNull(attribute);
    Assertions.assertEquals("urn:oid:1.2.752.29.4.13", attribute.getName());
    Assertions.assertEquals("195207306886", attribute.getAttributeValues().get(0));
  }

  @Test
  public void testToAttributeUnsupportedType() {
    Assertions.assertThrows(SignServiceProtocolException.class,
        () -> DssUtils.toAttribute(SignerIdentityAttributeValue.builder()
            .type("oidc").name("http://claim.xx.yy").value("195207306886").build()));
  }

  @Test
  public void testToAttributeValue() throws Exception {
    SignerIdentityAttributeValue siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.752.29.4.13")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("195207306886")
        .attributeValueType("string")
        .build();

    Object value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(value instanceof String);
    Assertions.assertEquals("195207306886", value);

    siav = SignerIdentityAttributeValue.builder()
        .name("urn:oid:1.2.752.29.4.13")
        .value("195207306886")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(value instanceof String);
    Assertions.assertEquals("195207306886", value);

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("true")
        .attributeValueType("boolean")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(value instanceof Boolean);
    Assertions.assertEquals(Boolean.TRUE, value);

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("0")
        .attributeValueType("boolean")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(value instanceof Boolean);
    Assertions.assertEquals(Boolean.FALSE, value);

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("123")
        .attributeValueType("integer")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(value instanceof BigInteger);
    Assertions.assertEquals(123, ((BigInteger) value).intValue());

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("1969-11-20")
        .attributeValueType("date")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(value instanceof XMLGregorianCalendar);
    Assertions.assertEquals(DatatypeFactory.newInstance().newXMLGregorianCalendar("1969-11-20"), value);

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("2002-05-30T09:00:00")
        .attributeValueType("dateTime")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(value instanceof XMLGregorianCalendar);
    Assertions.assertEquals(DatatypeFactory.newInstance().newXMLGregorianCalendar("2002-05-30T09:00:00"), value);
  }

  @Test
  public void testToAttributeValueUnsupportedValue() {
    final SignerIdentityAttributeValue siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.752.29.4.13")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("195207306886")
        .attributeValueType("weird-type")
        .build();

    Assertions.assertThrows(SignServiceProtocolException.class, () -> DssUtils.toAttributeValue(siav));
  }
}
