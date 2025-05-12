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

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.w3c.dom.Document;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.core.error.impl.SignServiceProtocolException;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.schemas.saml_2_0.assertion.Assertion;
import se.swedenconnect.schemas.saml_2_0.assertion.Attribute;
import se.swedenconnect.schemas.saml_2_0.assertion.AttributeStatement;
import se.swedenconnect.schemas.saml_2_0.assertion.NameIDType;

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
    final Resource resource = new ClassPathResource("assertion.xml");
    final Document doc = DOMUtils.inputStreamToDocument(resource.getInputStream());
    this.assertion = JAXBUnmarshaller.unmarshall(doc, Assertion.class);
  }

  @Test
  public void testEntity() {
    final NameIDType entity = DssUtils.toEntity("https://kalle.kula.se");
    Assert.assertNotNull(entity);
    Assert.assertEquals("https://kalle.kula.se", entity.getValue());
  }

  @Test
  public void testGetAttributeStatement() {
    final AttributeStatement statement = DssUtils.getAttributeStatement(this.assertion);
    Assert.assertNotNull(statement);
  }

  @Test
  public void testGetStringAttributeValue() {
    final AttributeStatement statement = DssUtils.getAttributeStatement(this.assertion);
    final String value = DssUtils.getAttributeValue(statement, "urn:oid:1.2.752.29.4.13");
    Assert.assertNotNull(value);
    Assert.assertEquals("195207306886", value);

    // The same, but not type info for the attribute value ...
    final String value2 = DssUtils.getAttributeValue(statement, "urn:oid:0.9.2342.19200300.100.1.3");
    Assert.assertNotNull(value2);
    Assert.assertEquals("john.doe@example.com", value2);

    // Not a string
    Assert.assertNull(DssUtils.getAttributeValue(statement, "urn:oid:2.16.840.1.113730.3.1.241"));

    // Not present
    Assert.assertNull(DssUtils.getAttributeValue(statement, "urn:oid:1.2.3.4.5"));
  }

  @Test
  public void testNpeFixInToSignerIdentityAttributeValue() throws Exception {
    final Assertion testAssertion;
    try (final InputStream is = DssUtilsTest.class.getClassLoader().getResourceAsStream("IS-75-saml-assertion.xml")) {
      final Document doc = DOMUtils.inputStreamToDocument(is);
      testAssertion = JAXBUnmarshaller.unmarshall(doc, Assertion.class);
    }
    final AttributeStatement attributeStatement = DssUtils.getAttributeStatement(testAssertion);

    final String value = DssUtils.getAttributeValue(attributeStatement, "urn:oid:1.3.6.1.4.1.5923.1.1.1.10");
    Assert.assertNotNull(value);
    Assert.assertEquals("IKXQZCJJPR7WF3L7TV7NVQV4MZO4F26M", value);

    final Attribute attr = attributeStatement.getAttributesAndEncryptedAttributes().stream()
        .filter(Attribute.class::isInstance)
        .map(Attribute.class::cast)
        .filter(a -> Objects.equals(a.getName(), "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"))
        .filter(Attribute::isSetAttributeValues)
        .findFirst()
        .orElse(null);
    final List<SignerIdentityAttributeValue> siav = DssUtils.toSignerIdentityAttributeValue(attr);
    Assert.assertNotNull(siav);
    Assert.assertEquals(1, siav.size());
    Assert.assertEquals("IKXQZCJJPR7WF3L7TV7NVQV4MZO4F26M", siav.get(0).getValue());

    final List<SignerIdentityAttributeValue> values = DssUtils.fromAttributeStatement(attributeStatement);
    Assert.assertNotNull(values);
    Assert.assertEquals(8, values.size());
  }

  @Test
  public void testGetAttributeValue() throws Exception {
    final AttributeStatement statement = DssUtils.getAttributeStatement(this.assertion);
    final String value = DssUtils.getAttributeValue(statement, "urn:oid:1.2.752.29.4.13", String.class);
    Assert.assertNotNull(value);
    Assert.assertEquals("195207306886", value);

    final XMLGregorianCalendar dateTime =
        DssUtils.getAttributeValue(statement, "urn:oid:2.16.840.1.113730.3.1.241", XMLGregorianCalendar.class);
    Assert.assertNotNull(dateTime);
    Assert.assertEquals(DatatypeFactory.newInstance().newXMLGregorianCalendar("2002-05-30T09:00:00"), dateTime);

    // Not present
    Assert.assertNull(DssUtils.getAttributeValue(statement, "urn:oid:1.2.3.4.5", String.class));
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
    Assert.assertNotNull(statement);
    Assert.assertTrue(statement.getAttributesAndEncryptedAttributes().size() == 2);
    Assert.assertEquals("195207306886", DssUtils.getAttributeValue(statement, "urn:oid:1.2.752.29.4.13"));
    Assert.assertEquals("value", DssUtils.getAttributeValue(statement, "urn:oid:1.2.3.4.5"));

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
    Assert.assertNotNull(statement2);
    Assert.assertTrue(statement2.getAttributesAndEncryptedAttributes().size() == 1);
    Assert.assertTrue(
        ((Attribute) statement2.getAttributesAndEncryptedAttributes().get(0)).getAttributeValues().size() == 2);
  }

  @Test
  public void testFromAttributeStatement() {
    final AttributeStatement statement = DssUtils.getAttributeStatement(this.assertion);
    final List<SignerIdentityAttributeValue> result = DssUtils.fromAttributeStatement(statement);
    Assert.assertEquals(6, result.size());
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
    Assert.assertNotNull(attribute);
    Assert.assertEquals("urn:oid:1.2.752.29.4.13", attribute.getName());
    Assert.assertEquals("195207306886", attribute.getAttributeValues().get(0));
  }

  @Test(expected = SignServiceProtocolException.class)
  public void testToAttributeUnsupportedType() throws Exception {
    DssUtils.toAttribute(SignerIdentityAttributeValue.builder()
        .type("oidc").name("http://claim.xx.yy").value("195207306886").build());
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
    Assert.assertTrue(value instanceof String);
    Assert.assertEquals("195207306886", value);

    siav = SignerIdentityAttributeValue.builder()
        .name("urn:oid:1.2.752.29.4.13")
        .value("195207306886")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assert.assertTrue(value instanceof String);
    Assert.assertEquals("195207306886", value);

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("true")
        .attributeValueType("boolean")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assert.assertTrue(value instanceof Boolean);
    Assert.assertEquals(Boolean.TRUE, value);

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("0")
        .attributeValueType("boolean")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assert.assertTrue(value instanceof Boolean);
    Assert.assertEquals(Boolean.FALSE, value);

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("123")
        .attributeValueType("integer")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assert.assertTrue(value instanceof BigInteger);
    Assert.assertEquals(123, ((BigInteger) value).intValue());

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("1969-11-20")
        .attributeValueType("date")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assert.assertTrue(value instanceof XMLGregorianCalendar);
    Assert.assertEquals(DatatypeFactory.newInstance().newXMLGregorianCalendar("1969-11-20"), value);

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("2002-05-30T09:00:00")
        .attributeValueType("dateTime")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assert.assertTrue(value instanceof XMLGregorianCalendar);
    Assert.assertEquals(DatatypeFactory.newInstance().newXMLGregorianCalendar("2002-05-30T09:00:00"), value);
  }

  @Test(expected = SignServiceProtocolException.class)
  public void testToAttributeValueUnsupportedValue() throws Exception {
    final SignerIdentityAttributeValue siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.752.29.4.13")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("195207306886")
        .attributeValueType("weird-type")
        .build();

    DssUtils.toAttributeValue(siav);
  }
}
