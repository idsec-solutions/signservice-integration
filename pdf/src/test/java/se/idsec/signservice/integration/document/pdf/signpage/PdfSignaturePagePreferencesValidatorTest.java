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
package se.idsec.signservice.integration.document.pdf.signpage;

import org.junit.Assert;
import org.junit.Test;

import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.impl.DefaultFileResource;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage.PdfSignatureImagePlacementConfiguration;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePagePreferences;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureUserInformation;
import se.idsec.signservice.integration.document.pdf.signpage.impl.PdfSignaturePagePreferencesValidator;

/**
 * Test cases for PdfSignaturePagePreferencesValidator.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PdfSignaturePagePreferencesValidatorTest {

  @Test
  public void testMissingPage() throws Exception {
    final PdfSignaturePagePreferencesValidator validator = new PdfSignaturePagePreferencesValidator();

    IntegrationServiceConfiguration config = DefaultIntegrationServiceConfiguration.builder()
      .policy("default")
      .build();

    // No page given, and no default exists ...
    //
    PdfSignaturePagePreferences object = PdfSignaturePagePreferences.builder().build();
    try {
      validator.validateObject(object, "prefs", config);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
    }

    // Reference given, but this does not exist in config
    //
    object = PdfSignaturePagePreferences.builder()
      .signaturePageReference("reference")
      .build();
    try {
      validator.validateObject(object, "prefs", config);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertNotNull(e.getDetails().get("prefs.signaturePageReference"));
    }

    config = DefaultIntegrationServiceConfiguration.builder()
      .policy("default")
      .pdfSignaturePage(PdfSignaturePage.builder()
        .id("PDF")
        .build())
      .build();

    try {
      validator.validateObject(object, "prefs", config);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertNotNull(e.getDetails().get("prefs.signaturePageReference"));
    }
  }

  @Test
  public void testBothReferenceAndPageGivenError() throws Exception {
    final PdfSignaturePagePreferencesValidator validator = new PdfSignaturePagePreferencesValidator();

    IntegrationServiceConfiguration config = DefaultIntegrationServiceConfiguration.builder()
      .policy("default")
      .build();

    PdfSignaturePagePreferences object = PdfSignaturePagePreferences.builder()
      .signaturePageReference("reference")
      .signaturePage(PdfSignaturePage.builder().id("ID").build())
      .build();

    try {
      validator.validateObject(object, "prefs", config);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
    }
  }

  @Test
  public void testMissingVisiblePdfSignatureUserInformation() throws Exception {
    final PdfSignaturePagePreferencesValidator validator = new PdfSignaturePagePreferencesValidator();

    IntegrationServiceConfiguration config = DefaultIntegrationServiceConfiguration.builder()
      .policy("default")
      .pdfSignatureImageTemplate(PdfSignatureImageTemplate.builder()
        .reference("template")
        .build())
      .build();

    PdfSignaturePagePreferences object = PdfSignaturePagePreferences.builder()
      .signaturePage(PdfSignaturePage.builder()
        .id("page")
        .pdfDocument(DefaultFileResource.builder()
          .resource("classpath:config/eduSign-page.pdf")
          .build())
        .signatureImageReference("template")
        .imagePlacementConfiguration(PdfSignatureImagePlacementConfiguration.builder()
          .xPosition(100)
          .yPosition(100)
          .build())
        .build())
      .build();

    try {
      validator.validateObject(object, "prefs", config);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertNotNull(e.getDetails().get("prefs.visiblePdfSignatureUserInformation"));
    }
  }

  @Test
  public void testInvalidVisiblePdfSignatureUserInformation_MissingTemplate() throws Exception {
    final PdfSignaturePagePreferencesValidator validator = new PdfSignaturePagePreferencesValidator();

    IntegrationServiceConfiguration config = DefaultIntegrationServiceConfiguration.builder()
      .policy("default")
      .build();

    PdfSignaturePagePreferences object = PdfSignaturePagePreferences.builder()
      .signaturePage(PdfSignaturePage.builder()
        .id("page")
        .pdfDocument(DefaultFileResource.builder()
          .resource("classpath:config/eduSign-page.pdf")
          .build())
        .signatureImageReference("template")
        .imagePlacementConfiguration(PdfSignatureImagePlacementConfiguration.builder()
          .xPosition(100)
          .yPosition(100)
          .build())
        .build())
      .visiblePdfSignatureUserInformation(VisiblePdfSignatureUserInformation.toBuilder()
        .fieldValue("A", "B")
        .build())
      .build();

    try {
      validator.validateObject(object, "prefs", config);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertNotNull(e.getDetails().get("prefs.signaturePage.signatureImageReference"));
      Assert.assertNull(e.getDetails().get("prefs.visiblePdfSignatureUserInformation"));
    }

    config = DefaultIntegrationServiceConfiguration.builder()
      .policy("default")
      .pdfSignaturePage(PdfSignaturePage.builder()
        .id("page")
        .pdfDocument(DefaultFileResource.builder()
          .resource("classpath:config/eduSign-page.pdf")
          .build())
        .signatureImageReference("template")
        .imagePlacementConfiguration(PdfSignatureImagePlacementConfiguration.builder()
          .xPosition(100)
          .yPosition(100)
          .build())
        .build())
      .build();

    object = PdfSignaturePagePreferences.builder()
      .signaturePageReference("page")
      .visiblePdfSignatureUserInformation(VisiblePdfSignatureUserInformation.toBuilder()
        .fieldValue("A", "B")
        .build())
      .build();

    try {
      validator.validateObject(object, "prefs", config);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      System.out.println(e.getMessage());
      Assert.assertNull(e.getDetails().get("prefs.signaturePage.signatureImageReference"));
      Assert.assertNotNull(e.getDetails().get("prefs.visiblePdfSignatureUserInformation"));
    }
  }

  @Test
  public void testSuccess() throws Exception {
    final PdfSignaturePagePreferencesValidator validator = new PdfSignaturePagePreferencesValidator();

    IntegrationServiceConfiguration config = DefaultIntegrationServiceConfiguration.builder()
      .policy("default")
      .pdfSignatureImageTemplate(PdfSignatureImageTemplate.builder()
        .reference("template")
        .includeSignerName(false)
        .field("A", "Desc")
        .build())
      .build();

    PdfSignaturePagePreferences object = PdfSignaturePagePreferences.builder()
      .signaturePage(PdfSignaturePage.builder()
        .id("page")
        .pdfDocument(DefaultFileResource.builder()
          .resource("classpath:config/eduSign-page.pdf")
          .build())
        .signatureImageReference("template")
        .imagePlacementConfiguration(PdfSignatureImagePlacementConfiguration.builder()
          .xPosition(100)
          .yPosition(100)
          .build())
        .build())
      .visiblePdfSignatureUserInformation(VisiblePdfSignatureUserInformation.toBuilder()
        .fieldValue("A", "B")
        .build())
      .build();

    validator.validateObject(object, "prefs", config);
    final ValidationResult result = validator.validate(object, "prefs", config);
    Assert.assertFalse(result.hasErrors());
  }

}
