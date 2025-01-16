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
package se.idsec.signservice.integration.document.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureUserInformation;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureUserInformation.SignerName;

/**
 * Test cases for VisiblePdfSignatureUserInformationValidator.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class VisiblePdfSignatureUserInformationValidatorTest {

  @Test
  public void testMissingHint() throws Exception {
    final VisiblePdfSignatureUserInformationValidator validator = new VisiblePdfSignatureUserInformationValidator();

    VisiblePdfSignatureUserInformation object = VisiblePdfSignatureUserInformation.toBuilder()
        .fieldValue("IDP", "eduSign IDP")
        .build();

    try {
      validator.validateObject(object, "name", null);
      Assertions.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
    }
  }

  @Test
  public void testSignerNameError() throws Exception {
    final VisiblePdfSignatureUserInformationValidator validator = new VisiblePdfSignatureUserInformationValidator();

    final PdfSignatureImageTemplate hint = PdfSignatureImageTemplate.builder()
        .reference("ref")
        .includeSignerName(true)
        .build();

    VisiblePdfSignatureUserInformation object = VisiblePdfSignatureUserInformation.toBuilder()
        .fieldValue("IDP", "eduSign IDP")
        .build();

    try {
      validator.validateObject(object, "name", hint);
      Assertions.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("name.signerName"));
    }

    object = VisiblePdfSignatureUserInformation.toBuilder()
        .signerName(SignerName.builder().build())
        .fieldValue("IDP", "eduSign IDP")
        .build();

    try {
      validator.validateObject(object, "name", hint);
      Assertions.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("name.signerName"));
    }

  }

  @Test
  public void testMissingFields() throws Exception {
    final VisiblePdfSignatureUserInformationValidator validator = new VisiblePdfSignatureUserInformationValidator();

    final PdfSignatureImageTemplate hint = PdfSignatureImageTemplate.builder()
        .reference("ref")
        .includeSignerName(true)
        .field("IDP", "Description")
        .field("Foo", "Description")
        .build();

    VisiblePdfSignatureUserInformation object = VisiblePdfSignatureUserInformation.toBuilder()
        .signerName(SignerName.builder()
            .signerAttribute(SignerIdentityAttribute.createBuilder().name("urn:oid:2.16.840.1.113730.3.1.241").build())
            .build())
        .build();

    try {
      validator.validateObject(object, "name", hint);
      Assertions.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("name.fieldValues.IDP"));
      Assertions.assertNotNull(e.getDetails().get("name.fieldValues.Foo"));
    }

    object = VisiblePdfSignatureUserInformation.toBuilder()
        .signerName(SignerName.builder()
            .signerAttribute(SignerIdentityAttribute.createBuilder().name("urn:oid:2.16.840.1.113730.3.1.241").build())
            .build())
        .fieldValue("IDP", "eduSign IDP")
        .build();

    try {
      validator.validateObject(object, "name", hint);
      Assertions.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("name.fieldValues.Foo"));
    }
  }

  @Test
  public void testSuccess() throws Exception {
    final VisiblePdfSignatureUserInformationValidator validator = new VisiblePdfSignatureUserInformationValidator();

    final PdfSignatureImageTemplate hint = PdfSignatureImageTemplate.builder()
        .reference("ref")
        .includeSignerName(true)
        .field("IDP", "Description")
        .field("Foo", "Description")
        .build();

    final VisiblePdfSignatureUserInformation object = VisiblePdfSignatureUserInformation.toBuilder()
        .signerName(SignerName.builder()
            .signerAttribute(SignerIdentityAttribute.createBuilder().name("urn:oid:2.16.840.1.113730.3.1.241").build())
            .build())
        .fieldValue("IDP", "eduSign IDP")
        .fieldValue("foo", "value")
        .build();

    validator.validateObject(object, "name", hint);
    final ValidationResult result = validator.validate(object, "name", hint);
    Assertions.assertFalse(result.hasErrors());
  }
}
