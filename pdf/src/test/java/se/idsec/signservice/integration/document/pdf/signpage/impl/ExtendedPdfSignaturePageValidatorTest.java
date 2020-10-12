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
package se.idsec.signservice.integration.document.pdf.signpage.impl;

import java.util.Arrays;
import java.util.Base64;

import org.junit.Assert;
import org.junit.Test;

import se.idsec.signservice.integration.config.impl.DefaultFileResource;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.impl.PdfSignaturePageValidator;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage.PdfSignatureImagePlacementConfiguration;

/**
 * Test cases for ExtendedPdfSignaturePageValidator.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedPdfSignaturePageValidatorTest {

  @Test
  public void testInvalidPdfDocument() throws Exception {
    final PdfSignaturePageValidator validator = new ExtendedPdfSignaturePageValidator();
    
    final PdfSignaturePage page = PdfSignaturePage.builder()
        .id("ID")
        .pdfDocument(DefaultFileResource.builder()
          .contents(Base64.getEncoder().encodeToString("ABC".getBytes()))
          .build())
        .build();
    
    try {
      validator.validateObject(page, "page", null);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertNotNull(e.getDetails().get("page.pdfDocument"));
    }
  }
  
  @Test
  public void testInvalidPage() throws Exception {
    final PdfSignaturePageValidator validator = new ExtendedPdfSignaturePageValidator();
    
    final PdfSignaturePage page = PdfSignaturePage.builder()
        .id("ID")
        .pdfDocument(DefaultFileResource.builder()
          .resource("classpath:config/eduSign-page.pdf")
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
          .page(2)  // The loaded page only has 1 page ...
          .build())
        .build();
    
    final PdfSignatureImageTemplate template = PdfSignatureImageTemplate.builder()
        .reference("ref1")
        .build();
    
    try {
      validator.validateObject(page, "page", Arrays.asList(template));
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertNotNull(e.getDetails().get("page.imagePlacementConfiguration.page"));
      Assert.assertEquals(1, e.getDetails().size());
    }
  }
  
  @Test
  public void testSuccess() throws Exception {
    final PdfSignaturePageValidator validator = new ExtendedPdfSignaturePageValidator();
    
    final PdfSignaturePage page = PdfSignaturePage.builder()
        .id("ID")
        .pdfDocument(DefaultFileResource.builder()
          .resource("classpath:config/eduSign-page.pdf")
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
          .page(0)
          .build())
        .build();
    
    final PdfSignatureImageTemplate template = PdfSignatureImageTemplate.builder()
        .reference("ref1")
        .build();
    
    validator.validateObject(page, "page", Arrays.asList(template));
    final ValidationResult result = validator.validate(page, "page", Arrays.asList(template));
    Assert.assertFalse(result.hasErrors());
  }
  
}
