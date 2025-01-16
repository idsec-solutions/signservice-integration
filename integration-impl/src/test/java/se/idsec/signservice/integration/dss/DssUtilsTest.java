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

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
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

/**
 * Test cases for DssUtils.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DssUtilsTest {

  private Assertion assertion;

  public DssUtilsTest() throws Exception {
    final Resource resource = new ClassPathResource("assertion.xml");
    final Document doc = DOMUtils.inputStreamToDocument(resource.getInputStream());
    this.assertion = JAXBUnmarshaller.unmarshall(doc, Assertion.class);
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
  public void testFromAttributeStatement() throws Exception {
    final AttributeStatement statement = DssUtils.getAttributeStatement(this.assertion);
    List<SignerIdentityAttributeValue> result = DssUtils.fromAttributeStatement(statement);
    Assertions.assertEquals(5, result.size());
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
  public void testToAttributeUnsupportedType() throws Exception {
    Assertions.assertThrows(SignServiceProtocolException.class, () -> {
      DssUtils.toAttribute(SignerIdentityAttributeValue.builder()
          .type("oidc").name("http://claim.xx.yy").value("195207306886").build());
    });
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
    Assertions.assertTrue(String.class.isInstance(value));
    Assertions.assertEquals("195207306886", value);

    siav = SignerIdentityAttributeValue.builder()
        .name("urn:oid:1.2.752.29.4.13")
        .value("195207306886")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(String.class.isInstance(value));
    Assertions.assertEquals("195207306886", value);

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("true")
        .attributeValueType("boolean")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(Boolean.class.isInstance(value));
    Assertions.assertEquals(Boolean.TRUE, value);

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("0")
        .attributeValueType("boolean")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(Boolean.class.isInstance(value));
    Assertions.assertEquals(Boolean.FALSE, value);

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("123")
        .attributeValueType("integer")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(BigInteger.class.isInstance(value));
    Assertions.assertEquals(123, BigInteger.class.cast(value).intValue());

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("1969-11-20")
        .attributeValueType("date")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(XMLGregorianCalendar.class.isInstance(value));
    Assertions.assertEquals(DatatypeFactory.newInstance().newXMLGregorianCalendar("1969-11-20"), value);

    siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.3.4.5")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("2002-05-30T09:00:00")
        .attributeValueType("dateTime")
        .build();

    value = DssUtils.toAttributeValue(siav);
    Assertions.assertTrue(XMLGregorianCalendar.class.isInstance(value));
    Assertions.assertEquals(DatatypeFactory.newInstance().newXMLGregorianCalendar("2002-05-30T09:00:00"), value);
  }

  @Test
  public void testToAttributeValueUnsupportedValue() throws Exception {
    final SignerIdentityAttributeValue siav = SignerIdentityAttributeValue.builder()
        .type(SignerIdentityAttribute.SAML_TYPE)
        .name("urn:oid:1.2.752.29.4.13")
        .nameFormat(SignerIdentityAttributeValue.DEFAULT_NAME_FORMAT)
        .value("195207306886")
        .attributeValueType("weird-type")
        .build();

    Assertions.assertThrows(SignServiceProtocolException.class, () -> {
      DssUtils.toAttributeValue(siav);
    });
  }
}
