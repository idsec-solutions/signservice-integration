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
package se.idsec.signservice.integration.document.impl;

import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.idsec.signservice.integration.core.FileResource;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage.PdfSignatureImagePlacementConfiguration;

/**
 * Test cases for PdfSignaturePageValidator.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PdfSignaturePageValidatorTest {

  @Test
  public void testMissingId() throws Exception {
    final PdfSignaturePageValidator validator = new PdfSignaturePageValidator();

    try {
      validator.validateObject(new PdfSignaturePage(), "page", null);
      Assertions.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("page.id"));
    }
  }

  @Test
  public void testMissingDocument() throws Exception {
    final PdfSignaturePageValidator validator = new PdfSignaturePageValidator();

    try {
      validator.validateObject(PdfSignaturePage.builder().id("ID").build(), "page", null);
      Assertions.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assertions.assertNull(e.getDetails().get("page.id"));
      Assertions.assertNotNull(e.getDetails().get("page.pdfDocument"));
    }
  }

  @Test
  public void testMissingTemplateReference() throws Exception {
    final PdfSignaturePageValidator validator = new PdfSignaturePageValidator();

    final PdfSignaturePage page = PdfSignaturePage.builder()
        .id("ID")
        .pdfDocument(FileResource.builder()
          .contents(Base64.getEncoder().encodeToString("ABC".getBytes()))
          .build())
        .build();

    try {
      validator.validateObject(page, "page", null);
      Assertions.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assertions.assertNull(e.getDetails().get("page.id"));
      Assertions.assertNull(e.getDetails().get("page.pdfDocument"));
      Assertions.assertNotNull(e.getDetails().get("page.signatureImageReference"));
    }
  }

  @Test
  public void testIllegalTemplateReference() throws Exception {
    final PdfSignaturePageValidator validator = new PdfSignaturePageValidator();

    final PdfSignaturePage page = PdfSignaturePage.builder()
        .id("ID")
        .pdfDocument(FileResource.builder()
          .contents(Base64.getEncoder().encodeToString("ABC".getBytes()))
          .build())
        .signatureImageReference("not-found")
        .build();

    try {
      validator.validateObject(page, "page", null);
      Assertions.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("page.signatureImageReference"));
    }

    final PdfSignatureImageTemplate template = PdfSignatureImageTemplate.builder()
        .reference("ref1")
        .build();

    try {
      validator.validateObject(page, "page", Arrays.asList(template));
      Assertions.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("page.signatureImageReference"));
    }
  }

  @Test
  public void testMissingImagePlacementConfiguration() throws Exception {
    final PdfSignaturePageValidator validator = new PdfSignaturePageValidator();

    final PdfSignaturePage page = PdfSignaturePage.builder()
        .id("ID")
        .pdfDocument(FileResource.builder()
          .contents(Base64.getEncoder().encodeToString("ABC".getBytes()))
          .build())
        .signatureImageReference("ref1")
        .build();

    final PdfSignatureImageTemplate template = PdfSignatureImageTemplate.builder()
        .reference("ref1")
        .build();

    try {
      validator.validateObject(page, "page", Arrays.asList(template));
      Assertions.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("page.imagePlacementConfiguration"));
    }
  }

  @Test
  public void testInvalidImagePlacementConfiguration() throws Exception {
    final PdfSignaturePageValidator validator = new PdfSignaturePageValidator();

    PdfSignaturePage page = PdfSignaturePage.builder()
        .id("ID")
        .pdfDocument(FileResource.builder()
          .contents(Base64.getEncoder().encodeToString("ABC".getBytes()))
          .build())
        .signatureImageReference("ref1")
        .imagePlacementConfiguration(new PdfSignatureImagePlacementConfiguration())
        .build();

    final PdfSignatureImageTemplate template = PdfSignatureImageTemplate.builder()
        .reference("ref1")
        .build();

    // Missing X
    try {
      validator.validateObject(page, "page", Arrays.asList(template));
      Assertions.fail("Expected InputValidationException due to missing xPosition");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("page.imagePlacementConfiguration.xPosition"));

      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.xIncrement"));
      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.yIncrement"));
    }

    // Invalid value for X
    page.getImagePlacementConfiguration().setXPosition(-10);
    try {
      validator.validateObject(page, "page", Arrays.asList(template));
      Assertions.fail("Expected InputValidationException due to invalid xPosition");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("page.imagePlacementConfiguration.xPosition"));

      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.xIncrement"));
      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.yIncrement"));
    }

    // Missing Y
    page.getImagePlacementConfiguration().setXPosition(10);
    try {
      validator.validateObject(page, "page", Arrays.asList(template));
      Assertions.fail("Expected InputValidationException due to missing yPosition");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("page.imagePlacementConfiguration.yPosition"));

      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.xPosition"));
      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.xIncrement"));
      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.yIncrement"));
    }

    // Invalid value for Y
    page.getImagePlacementConfiguration().setYPosition(-10);
    try {
      validator.validateObject(page, "page", Arrays.asList(template));
      Assertions.fail("Expected InputValidationException due to invalid yPosition");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("page.imagePlacementConfiguration.yPosition"));

      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.xPosition"));
      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.xIncrement"));
      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.yIncrement"));
    }

    // Missing X increment
    page.getImagePlacementConfiguration().setYPosition(10);
    page.setColumns(2);
    try {
      validator.validateObject(page, "page", Arrays.asList(template));
      Assertions.fail("Expected InputValidationException due to missing xIncrement");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("page.imagePlacementConfiguration.xIncrement"));

      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.xPosition"));
      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.yPosition"));
      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.yIncrement"));
    }

    // Missing Y increment
    page.setRows(2);
    page.getImagePlacementConfiguration().setXIncrement(100);
    try {
      validator.validateObject(page, "page", Arrays.asList(template));
      Assertions.fail("Expected InputValidationException due to missing yIncrement");
    }
    catch (InputValidationException e) {
      Assertions.assertNotNull(e.getDetails().get("page.imagePlacementConfiguration.yIncrement"));

      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.xPosition"));
      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.yPosition"));
      Assertions.assertNull(e.getDetails().get("page.imagePlacementConfiguration.xIncrement"));
    }
  }

  @Test
  public void testSuccess() throws Exception {
    final PdfSignaturePageValidator validator = new PdfSignaturePageValidator();

    final PdfSignaturePage page = PdfSignaturePage.builder()
        .id("ID")
        .pdfDocument(FileResource.builder()
          .contents(Base64.getEncoder().encodeToString("ABC".getBytes()))
          .build())
        .signatureImageReference("ref1")
        .rows(2)
        .columns(2)
        .imagePlacementConfiguration(PdfSignatureImagePlacementConfiguration.builder()
          .xPosition(10)
          .yPosition(10)
          .xIncrement(100)
          .yIncrement(100)
          .yIncrement(100)
          .build())
        .build();

    final PdfSignatureImageTemplate template = PdfSignatureImageTemplate.builder()
        .reference("ref1")
        .build();

    validator.validateObject(page, "page", Arrays.asList(template));
    final ValidationResult result = validator.validate(page, "page", Arrays.asList(template));
    Assertions.assertFalse(result.hasErrors());
  }

}
