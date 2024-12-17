/*
 * Copyright 2019-2023 IDsec Solutions AB
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
package se.idsec.signservice.integration.document.pdf;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.FileResource;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.impl.VisiblePdfSignatureRequirementValidator;

import java.util.Base64;

/**
 * Test cases for VisiblePdfSignatureRequirementValidator.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class VisiblePdfSignatureRequirementValidatorTest {

  private final static String OBJECT_NAME = "visiblePdfSignatureRequirement";

  // The validator that we are testing
  private final VisiblePdfSignatureRequirementValidator validator = new VisiblePdfSignatureRequirementValidator();

  // The test configuration
  private final IntegrationServiceConfiguration configuration;

  public VisiblePdfSignatureRequirementValidatorTest() {
    this.configuration =
        DefaultIntegrationServiceConfiguration.builder()
            .defaultVisiblePdfSignatureRequirement(null)
            .pdfSignatureImageTemplate(
                PdfSignatureImageTemplate.builder()
                    .reference("ref1")
                    .svgImageFile(
                        FileResource.builder().contents(
                            Base64.getEncoder().encodeToString("<svg>DUMMY</svg>".getBytes())).build())
                    .height(100)
                    .width(100)
                    .includeSignerName(false)
                    .includeSigningTime(false)
                    .build())
            .pdfSignatureImageTemplate(
                PdfSignatureImageTemplate.builder()
                    .reference("ref2")
                    .svgImageFile(
                        FileResource.builder().contents(
                            Base64.getEncoder().encodeToString("<svg>DUMMY</svg>".getBytes())).build())
                    .height(100)
                    .width(100)
                    .includeSignerName(true)
                    .includeSigningTime(false)
                    .build())
            .pdfSignatureImageTemplate(
                PdfSignatureImageTemplate.builder()
                    .reference("ref3")
                    .svgImageFile(
                        FileResource.builder().contents(
                            Base64.getEncoder().encodeToString("<svg>DUMMY</svg>".getBytes())).build())
                    .height(100)
                    .width(100)
                    .includeSignerName(false)
                    .includeSigningTime(false)
                    .field("abc", "abc decription")
                    .build())
            .build();
  }

  @Test
  public void testEmpty() {
    final ValidationResult result = this.validator.validate(null, OBJECT_NAME, this.configuration);
    Assertions.assertFalse(result.hasErrors());
    Assertions.assertEquals(OBJECT_NAME, result.getObjectName());
  }

  @Test
  public void testTemplateImageRef() {

    // Missing template reference
    //
    VisiblePdfSignatureRequirement req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef(null)
        .xPosition(100)
        .yPosition(100)
        .build();

    ValidationResult result = this.validator.validate(req, OBJECT_NAME, this.configuration);

    Assertions.assertTrue(result.hasErrors());
    Assertions.assertNotNull(result.getFieldErrors().get(OBJECT_NAME + ".templateImageRef"));
    Assertions.assertNotNull(result.getFieldErrors().get(OBJECT_NAME + ".visiblePdfSignatureRequirement"));
    Assertions.assertEquals(2, result.getFieldErrors().size());

    // The template reference does not exist in the configuration
    //
    req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef("non-existing-reference")
        .xPosition(100)
        .yPosition(100)
        .build();
    result = this.validator.validate(req, OBJECT_NAME, this.configuration);
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertNotNull(result.getFieldErrors().get(OBJECT_NAME + ".templateImageRef"));
    Assertions.assertNotNull(result.getFieldErrors().get(OBJECT_NAME + ".visiblePdfSignatureRequirement"));
    Assertions.assertEquals(2, result.getFieldErrors().size());

    // OK case
    //
    req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef("ref1")
        .xPosition(100)
        .yPosition(100)
        .build();
    result = this.validator.validate(req, OBJECT_NAME, this.configuration);
    Assertions.assertFalse(result.hasErrors());
  }

  @Test
  public void testPositions() {

    // Missing position
    //
    VisiblePdfSignatureRequirement req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef("ref1")
        .xPosition(null)
        .yPosition(100)
        .build();

    ValidationResult result = this.validator.validate(req, OBJECT_NAME, this.configuration);

    Assertions.assertTrue(result.hasErrors());
    Assertions.assertNotNull(result.getFieldErrors().get(OBJECT_NAME + ".xPosition"));
    Assertions.assertEquals(1, result.getFieldErrors().size());

    req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef("ref1")
        .xPosition(100)
        .yPosition(null)
        .build();

    result = this.validator.validate(req, OBJECT_NAME, this.configuration);

    Assertions.assertTrue(result.hasErrors());
    Assertions.assertNotNull(result.getFieldErrors().get(OBJECT_NAME + ".yPosition"));
    Assertions.assertEquals(1, result.getFieldErrors().size());

    // Bad value
    //
    req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef("ref1")
        .xPosition(-100)
        .yPosition(-100)
        .build();

    result = this.validator.validate(req, OBJECT_NAME, this.configuration);

    Assertions.assertTrue(result.hasErrors());
    Assertions.assertNotNull(result.getFieldErrors().get(OBJECT_NAME + ".xPosition"));
    Assertions.assertNotNull(result.getFieldErrors().get(OBJECT_NAME + ".yPosition"));
    Assertions.assertEquals(2, result.getFieldErrors().size());
  }

  @Test
  public void testSignerName() {

    // No signer name
    //
    VisiblePdfSignatureRequirement req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef("ref1")
        .xPosition(100)
        .yPosition(100)
        .signerName(null)
        .build();

    // Should work for template ref1 since it doesn't require signer name
    ValidationResult result = this.validator.validate(req, OBJECT_NAME, this.configuration);
    Assertions.assertFalse(result.hasErrors());

    // Should fail for template ref2 since it requires signer name
    req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef("ref2")
        .xPosition(100)
        .yPosition(100)
        .signerName(null)
        .build();

    result = this.validator.validate(req, OBJECT_NAME, this.configuration);
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertNotNull(result.getFieldErrors().get(OBJECT_NAME + ".signerName"));

    // Should fail if we have a signer name but no attributes
    req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef("ref2")
        .xPosition(100)
        .yPosition(100)
        .signerName(new VisiblePdfSignatureRequirement.SignerName())
        .build();

    result = this.validator.validate(req, OBJECT_NAME, this.configuration);
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertNotNull(result.getFieldErrors().get(OBJECT_NAME + ".signerName"));

    // Successful case
    req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef("ref2")
        .xPosition(100)
        .yPosition(100)
        .signerName(VisiblePdfSignatureRequirement.SignerName.builder()
            .signerAttribute(
                SignerIdentityAttribute.createBuilder().name("urn:oid:2.16.840.1.113730.3.1.241").build())
            .build())
        .build();

    result = this.validator.validate(req, OBJECT_NAME, this.configuration);
    Assertions.assertFalse(result.hasErrors());
  }

  @Test
  public void testFields() {

    // Template ref3 requires the field "abc" to be supplied
    //
    VisiblePdfSignatureRequirement req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef("ref3")
        .xPosition(100)
        .yPosition(100)
        .build();

    // Should work for template ref1 since it doesn't require signer name
    ValidationResult result = this.validator.validate(req, OBJECT_NAME, this.configuration);
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertNotNull(result.getFieldErrors().get(OBJECT_NAME + ".fieldValues.abc"));

    // A field value is given but the one that is required by the template
    req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef("ref3")
        .xPosition(100)
        .yPosition(100)
        .fieldValue("xyz", "The value")
        .build();

    result = this.validator.validate(req, OBJECT_NAME, this.configuration);
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertNotNull(result.getFieldErrors().get(OBJECT_NAME + ".fieldValues.abc"));

    // Successful case
    req = VisiblePdfSignatureRequirement.builder()
        .templateImageRef("ref3")
        .xPosition(100)
        .yPosition(100)
        .fieldValue("abc", "The value")
        .fieldValue("xyz", "The value")
        .build();

    result = this.validator.validate(req, OBJECT_NAME, this.configuration);
    Assertions.assertFalse(result.hasErrors());
  }
}
