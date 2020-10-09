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

import java.io.IOException;

import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.impl.DefaultFileResource;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage.PdfSignatureImagePlacementConfiguration;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePageFullException;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePagePreferences;
import se.idsec.signservice.integration.document.pdf.PreparedPdfDocument;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureRequirement;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureUserInformation;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureUserInformation.SignerName;

/**
 * Test cases for DefaultPdfSignaturePagePreparator.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultPdfSignaturePagePreparatorTest {
  
  private IntegrationServiceConfiguration config;
  
  public DefaultPdfSignaturePagePreparatorTest() {
    
    // Only set config settings relevant for PDF pages and PDF visible signatures ...
    //
    this.config = DefaultIntegrationServiceConfiguration.builder()
        .policy("test1")
        .pdfSignatureImageTemplate(PdfSignatureImageTemplate.builder()
          .reference("default-template")
          .svgImageFile(DefaultFileResource.builder()
              .resource("classpath:config/eduSign-image.svg")
              .description("Sign image for eduSign")
              .build())
          .height(351)
          .width(967)
          .includeSignerName(true)
          .includeSigningTime(true)
          .field("IDP", "The textual description of the IdP")
          .build())
        .pdfSignaturePage(PdfSignaturePage.builder()
          .id("default-sign-page")
          .pdfDocument(DefaultFileResource.builder()
            .resource("classpath:config/eduSign-page.pdf")
            .description("Sign page for eduSign")
            .build())
          .rows(4)
          .columns(2)
          .signatureImageReference("default-template")
          .imagePlacementConfiguration(PdfSignatureImagePlacementConfiguration.builder()
            .xPosition(37)
            .xIncrement(268)
            .yPosition(165)
            .yIncrement(105)
            .scale(-74)
            .build())
          .build())
        .build();    
  }
  
  @Test
  public void testMissingParameter() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    
    try {
      preparator.preparePdfSignaturePage(loadContents("pdf/sample-8-signatures.pdf"), null, this.config);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertEquals("signaturePagePreferences", e.getObjectName());
    }
    
    try {
      preparator.preparePdfSignaturePage(null, getDefaultPrefs(), this.config);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertEquals("pdfDocument", e.getObjectName());
    }
    
    try {
      preparator.preparePdfSignaturePage(loadContents("pdf/sample-8-signatures.pdf"), getDefaultPrefs(), null);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertEquals("policy", e.getObjectName());
    }
  }
  
  @Test
  public void testInvalidPdfBytes() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    try {
      preparator.preparePdfSignaturePage("ABCDEF".getBytes(), getDefaultPrefs(), this.config);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertEquals("pdfDocument", e.getObjectName());
      Assert.assertTrue(DocumentProcessingException.class.isInstance(e.getCause()));
    }
  }
  
  @Test
  public void testSignPageFull() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    PdfSignaturePagePreferences prefs = getDefaultPrefs();
    final PreparedPdfDocument result = preparator.preparePdfSignaturePage(
      loadContents("pdf/sample-8-signatures.pdf"), prefs, this.config);
    
    Assert.assertNull(result.getUpdatedPdfDocument());
    Assert.assertEquals("true", result.getVisiblePdfSignatureRequirement().getExtensionValue(
      VisiblePdfSignatureRequirement.NULL_INDICATOR_EXTENSION));
    
    // The same, but this time we don't accept a full page ...
    //
    prefs.setFailWhenSignPageFull(true);
    try {
      preparator.preparePdfSignaturePage(loadContents("pdf/sample-8-signatures.pdf"), prefs, this.config);
      Assert.fail("Expected PdfSignaturePageFullException");
    }
    catch (PdfSignaturePageFullException e) {      
    }
  }
  
  @Test
  public void testInsertPage() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    final PdfSignaturePagePreferences prefs = getDefaultPrefs();
    final PreparedPdfDocument result = preparator.preparePdfSignaturePage(
      loadContents("pdf/sample-0-signature.pdf"), prefs, this.config);
    
    Assert.assertNotNull(result.getUpdatedPdfDocument());
    // TODO: More checks
  }
  
  private static PdfSignaturePagePreferences getDefaultPrefs() {
    return PdfSignaturePagePreferences.builder()
        .signaturePageReference("default-sign-page")
        .visiblePdfSignatureUserInformation(VisiblePdfSignatureUserInformation.toBuilder()
          .signerName(SignerName.builder()
            .signerAttribute(SignerIdentityAttribute.createBuilder().name("urn:oid:2.16.840.1.113730.3.1.241").build())
            .build())
          .fieldValue("IDP", "eduID Sverige")
          .build())
        .failWhenSignPageFull(false)
        .build();
  }
  
  private static byte[] loadContents(final String resource) throws IOException {
    return IOUtils.toByteArray((new ClassPathResource(resource)).getInputStream());
  }
  
  private static PDDocument loadPdfDocument(final String resource) throws IOException {
    return PDDocument.load((new ClassPathResource(resource)).getInputStream());
  }
  
}
