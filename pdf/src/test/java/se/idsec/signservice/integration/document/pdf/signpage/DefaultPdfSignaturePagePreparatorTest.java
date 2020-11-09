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
import java.util.Base64;

import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import se.idsec.signservice.integration.SignServiceIntegrationService;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.DocumentCache;
import se.idsec.signservice.integration.core.FileResource;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.NoAccessException;
import se.idsec.signservice.integration.core.impl.InMemoryDocumentCache;
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
import se.idsec.signservice.integration.document.pdf.utils.PDDocumentUtils;

/**
 * Test cases for DefaultPdfSignaturePagePreparator.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultPdfSignaturePagePreparatorTest {

  private DefaultIntegrationServiceConfiguration configStateless;
  private DefaultIntegrationServiceConfiguration configStateful;

  private static final int xPosition = 37;
  private static final int xIncrement = 268;
  private static final int yPosition = 165;
  private static final int yIncrement = 105;
  private static final int scale = -74;

  public DefaultPdfSignaturePagePreparatorTest() {

    // Only set config settings relevant for PDF pages and PDF visible signatures ...
    //
    this.configStateless = DefaultIntegrationServiceConfiguration.builder()
      .policy("stateless-policy")
      .pdfSignatureImageTemplate(PdfSignatureImageTemplate.builder()
        .reference("default-template")
        .svgImageFile(FileResource.builder()
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
        .pdfDocument(FileResource.builder()
          .resource("classpath:config/eduSign-page.pdf")
          .description("Sign page for eduSign")
          .build())
        .rows(4)
        .columns(2)
        .signatureImageReference("default-template")
        .imagePlacementConfiguration(PdfSignatureImagePlacementConfiguration.builder()
          .xPosition(xPosition)
          .xIncrement(xIncrement)
          .yPosition(yPosition)
          .yIncrement(yIncrement)
          .scale(scale)
          .build())
        .build())
      .stateless(true)
      .build();
    this.configStateful = this.configStateless.toBuilder()
      .policy("stateful-policy")
      .stateless(false)
      .build();
  }

  @Test
  public void testMissingParameter() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();

    try {
      preparator.preparePdfSignaturePage(loadContents("pdf/sample-8-signatures.pdf"), null, this.configStateless);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertEquals("signaturePagePreferences", e.getObjectName());
    }

    try {
      preparator.preparePdfSignaturePage(null, getDefaultPrefs(), this.configStateless);
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
      preparator.preparePdfSignaturePage("ABCDEF".getBytes(), getDefaultPrefs(), this.configStateless);
      Assert.fail("Expected InputValidationException");
    }
    catch (InputValidationException e) {
      Assert.assertEquals("pdfDocument", e.getObjectName());
      Assert.assertTrue(DocumentProcessingException.class.isInstance(e.getCause()));
    }
  }

  @Test
  public void testPdfEncrypted() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    PdfSignaturePagePreferences prefs = getDefaultPrefs();

    try {
      preparator.preparePdfSignaturePage(loadContents("pdf/sample-encrypted.pdf"), prefs, this.configStateless);
    }
    catch (InputValidationException e) {
      Assert.assertEquals("pdfDocument", e.getObjectName());
    }
  }

  @Test
  public void testSignPageFull() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    PdfSignaturePagePreferences prefs = getDefaultPrefs();
    final PreparedPdfDocument result = preparator.preparePdfSignaturePage(
      loadContents("pdf/sample-8-signatures.pdf"), prefs, this.configStateless);

    Assert.assertNull(result.getUpdatedPdfDocument());
    Assert.assertEquals("stateless-policy", result.getPolicy());
    Assert.assertEquals("true", result.getVisiblePdfSignatureRequirement()
      .getExtensionValue(
        VisiblePdfSignatureRequirement.NULL_INDICATOR_EXTENSION));

    // The same, but this time we don't accept a full page ...
    //
    prefs.setFailWhenSignPageFull(true);
    try {
      preparator.preparePdfSignaturePage(loadContents("pdf/sample-8-signatures.pdf"), prefs, this.configStateless);
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
      loadContents("pdf/sample-0-signature.pdf"), prefs, this.configStateless);

    Assert.assertNotNull(result.getUpdatedPdfDocument());

    final PDDocument doc = PDDocumentUtils.load(Base64.getDecoder().decode(result.getUpdatedPdfDocument()));
    Assert.assertEquals(2, doc.getNumberOfPages());
    PDDocumentUtils.close(doc);

    Assert.assertEquals("stateless-policy", result.getPolicy());
    final VisiblePdfSignatureRequirement reqs = result.getVisiblePdfSignatureRequirement();
    Assert.assertEquals("default-template", reqs.getTemplateImageRef());
    Assert.assertEquals(2, reqs.getPage().intValue());
    Assert.assertEquals(xPosition, reqs.getXPosition().intValue());
    Assert.assertEquals(yPosition, reqs.getYPosition().intValue());
    Assert.assertEquals(scale, reqs.getScale().intValue());
    Assert.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getFieldValues(), reqs.getFieldValues());
    Assert.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().size(),
      reqs.getSignerName().getSignerAttributes().size());
    Assert.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().get(0).getName(),
      reqs.getSignerName().getSignerAttributes().get(0).getName());
    Assert.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getFormatting(), reqs.getSignerName()
      .getFormatting());
  }

  @Test
  public void testInsertPageReturnReference() throws Exception {
    
    final DocumentCache docCache = new InMemoryDocumentCache();
    
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    preparator.setDocumentCache(docCache);
    
    final PdfSignaturePagePreferences prefs = getDefaultPrefs();
    prefs.setReturnDocumentReference(true);
    final PreparedPdfDocument result = preparator.preparePdfSignaturePage(
      loadContents("pdf/sample-0-signature.pdf"), prefs, this.configStateful);

    Assert.assertNull(result.getUpdatedPdfDocument());
    Assert.assertNotNull(result.getUpdatedPdfDocumentReference());
    final String updatedDocument = docCache.get(result.getUpdatedPdfDocumentReference(), null);

    final PDDocument doc = PDDocumentUtils.load(Base64.getDecoder().decode(updatedDocument));
    Assert.assertEquals(2, doc.getNumberOfPages());
    PDDocumentUtils.close(doc);

    Assert.assertEquals("stateful-policy", result.getPolicy());
    final VisiblePdfSignatureRequirement reqs = result.getVisiblePdfSignatureRequirement();
    Assert.assertEquals("default-template", reqs.getTemplateImageRef());
    Assert.assertEquals(2, reqs.getPage().intValue());
    Assert.assertEquals(xPosition, reqs.getXPosition().intValue());
    Assert.assertEquals(yPosition, reqs.getYPosition().intValue());
    Assert.assertEquals(scale, reqs.getScale().intValue());
    Assert.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getFieldValues(), reqs.getFieldValues());
    Assert.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().size(),
      reqs.getSignerName().getSignerAttributes().size());
    Assert.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().get(0).getName(),
      reqs.getSignerName().getSignerAttributes().get(0).getName());
    Assert.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getFormatting(), reqs.getSignerName()
      .getFormatting());
  }

  @Test
  public void testNoNewPageUpdatedPos() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    final PdfSignaturePagePreferences prefs = getDefaultPrefs();
    PreparedPdfDocument result = preparator.preparePdfSignaturePage(
      loadContents("pdf/sample-1-signature.pdf"), prefs, this.configStateless);

    Assert.assertNull(result.getUpdatedPdfDocument());

    Assert.assertEquals("stateless-policy", result.getPolicy());
    VisiblePdfSignatureRequirement reqs = result.getVisiblePdfSignatureRequirement();
    Assert.assertEquals("default-template", reqs.getTemplateImageRef());
    Assert.assertEquals(2, reqs.getPage().intValue());
    Assert.assertEquals(xPosition + xIncrement, reqs.getXPosition().intValue());
    Assert.assertEquals(yPosition, reqs.getYPosition().intValue());
    Assert.assertEquals(scale, reqs.getScale().intValue());
    Assert.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getFieldValues(), reqs.getFieldValues());
    Assert.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().size(),
      reqs.getSignerName().getSignerAttributes().size());
    Assert.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().get(0).getName(),
      reqs.getSignerName().getSignerAttributes().get(0).getName());
    Assert.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getFormatting(), reqs.getSignerName()
      .getFormatting());

    result = preparator.preparePdfSignaturePage(
      loadContents("pdf/sample-2-signatures.pdf"), prefs, this.configStateless);

    Assert.assertNull(result.getUpdatedPdfDocument());

    reqs = result.getVisiblePdfSignatureRequirement();
    Assert.assertEquals(2, reqs.getPage().intValue());
    Assert.assertEquals(xPosition, reqs.getXPosition().intValue());
    Assert.assertEquals(yPosition + yIncrement, reqs.getYPosition().intValue());

    result = preparator.preparePdfSignaturePage(
      loadContents("pdf/sample-3-signatures.pdf"), prefs, this.configStateless);

    reqs = result.getVisiblePdfSignatureRequirement();
    Assert.assertEquals(xPosition + xIncrement, reqs.getXPosition().intValue());
    Assert.assertEquals(yPosition + yIncrement, reqs.getYPosition().intValue());

    result = preparator.preparePdfSignaturePage(
      loadContents("pdf/sample-4-signatures.pdf"), prefs, this.configStateless);

    reqs = result.getVisiblePdfSignatureRequirement();
    Assert.assertEquals(xPosition, reqs.getXPosition().intValue());
    Assert.assertEquals(yPosition + 2 * yIncrement, reqs.getYPosition().intValue());

    result = preparator.preparePdfSignaturePage(
      loadContents("pdf/sample-5-signatures.pdf"), prefs, this.configStateless);

    reqs = result.getVisiblePdfSignatureRequirement();
    Assert.assertEquals(xPosition + xIncrement, reqs.getXPosition().intValue());
    Assert.assertEquals(yPosition + 2 * yIncrement, reqs.getYPosition().intValue());

    result = preparator.preparePdfSignaturePage(
      loadContents("pdf/sample-6-signatures.pdf"), prefs, this.configStateless);

    reqs = result.getVisiblePdfSignatureRequirement();
    Assert.assertEquals(xPosition, reqs.getXPosition().intValue());
    Assert.assertEquals(yPosition + 3 * yIncrement, reqs.getYPosition().intValue());

    result = preparator.preparePdfSignaturePage(
      loadContents("pdf/sample-7-signatures.pdf"), prefs, this.configStateless);

    reqs = result.getVisiblePdfSignatureRequirement();
    Assert.assertEquals(xPosition + xIncrement, reqs.getXPosition().intValue());
    Assert.assertEquals(yPosition + 3 * yIncrement, reqs.getYPosition().intValue());
  }
  
  @Test
  public void testNoNewPageUpdatedPosReference() throws Exception {
    final DocumentCache docCache = new InMemoryDocumentCache();
    
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    preparator.setDocumentCache(docCache);
    
    final PdfSignaturePagePreferences prefs = getDefaultPrefs();
    prefs.setReturnDocumentReference(null);
    prefs.addExtensionValue(SignServiceIntegrationService.OWNER_ID_EXTENSION_KEY, "userid");
    final byte[] uploadedDocument = loadContents("pdf/sample-1-signature.pdf"); 
    PreparedPdfDocument result = preparator.preparePdfSignaturePage(
      uploadedDocument, prefs, this.configStateful);

    Assert.assertNull(result.getUpdatedPdfDocument());    
    Assert.assertNotNull(result.getUpdatedPdfDocumentReference());
    try {
      docCache.get(result.getUpdatedPdfDocumentReference(), null);
      Assert.fail("Expected NoAccessException");
    }
    catch (NoAccessException e) {      
    }
    try {
      docCache.get(result.getUpdatedPdfDocumentReference(), "otheruser");
      Assert.fail("Expected NoAccessException");
    }
    catch (NoAccessException e) {      
    }
    final String cachedDocument = docCache.get(result.getUpdatedPdfDocumentReference(), "userid");
    final byte[] cachedDocumentBytes = Base64.getDecoder().decode(cachedDocument);
    Assert.assertArrayEquals(uploadedDocument, cachedDocumentBytes);
    
    Assert.assertEquals("stateful-policy", result.getPolicy());
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

}
