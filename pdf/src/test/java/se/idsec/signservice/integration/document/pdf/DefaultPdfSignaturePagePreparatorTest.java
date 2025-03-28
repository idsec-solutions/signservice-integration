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
package se.idsec.signservice.integration.document.pdf;

import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.cryptacular.io.ClassPathResource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.DocumentCache;
import se.idsec.signservice.integration.core.FileResource;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.NoAccessException;
import se.idsec.signservice.integration.core.impl.InMemoryDocumentCache;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage.PdfSignatureImagePlacementConfiguration;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureUserInformation.SignerName;
import se.idsec.signservice.integration.document.pdf.utils.PDDocumentUtils;

import java.io.IOException;
import java.util.Base64;

/**
 * Test cases for DefaultPdfSignaturePagePreparator.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultPdfSignaturePagePreparatorTest {

  private final DefaultIntegrationServiceConfiguration configStateless;
  private final DefaultIntegrationServiceConfiguration configStateful;

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
      preparator.preparePdfDocument(null, getDefaultPrefs(), this.configStateless, null, null);
      Assertions.fail("Expected InputValidationException");
    }
    catch (final InputValidationException e) {
      Assertions.assertEquals("pdfDocument", e.getObjectName());
    }

    try {
      preparator.preparePdfDocument(loadContents("pdf/sample-8-signatures.pdf"), getDefaultPrefs(), null, null, null);
      Assertions.fail("Expected InputValidationException");
    }
    catch (final InputValidationException e) {
      Assertions.assertEquals("policy", e.getObjectName());
    }
  }

  @Test
  public void testInvalidPdfBytes() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    try {
      preparator.preparePdfDocument("ABCDEF".getBytes(), getDefaultPrefs(), this.configStateless, null, null);
      Assertions.fail("Expected InputValidationException");
    }
    catch (final InputValidationException e) {
      Assertions.assertEquals("pdfDocument", e.getObjectName());
      Assertions.assertTrue(e.getCause() instanceof DocumentProcessingException);
    }
  }

  @Test
  public void testPdfEncrypted() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    final PdfSignaturePagePreferences prefs = getDefaultPrefs();

    try {
      preparator.preparePdfDocument(loadContents("pdf/sample-encrypted.pdf"), prefs, this.configStateless, null, null);
    }
    catch (final InputValidationException e) {
      Assertions.assertEquals("pdfDocument", e.getObjectName());
    }
  }

  @Test
  public void testSignPageFull() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    final PdfSignaturePagePreferences prefs = getDefaultPrefs();
    final PreparedPdfDocument result = preparator.preparePdfDocument(
        loadContents("pdf/sample-8-signatures.pdf"), prefs, this.configStateless, null, null);

    Assertions.assertNull(result.getUpdatedPdfDocument());
    Assertions.assertEquals("stateless-policy", result.getPolicy());
    Assertions.assertEquals("true", result.getVisiblePdfSignatureRequirement()
        .getExtensionValue(
            VisiblePdfSignatureRequirement.NULL_INDICATOR_EXTENSION));

    // The same, but this time we don't accept a full page ...
    //
    prefs.setFailWhenSignPageFull(true);
    try {
      preparator.preparePdfDocument(loadContents("pdf/sample-8-signatures.pdf"), prefs, this.configStateless, null,
          null);
      Assertions.fail("Expected PdfSignaturePageFullException");
    }
    catch (final PdfSignaturePageFullException ignored) {
    }
  }

  @Test
  public void testInsertPage() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    final PdfSignaturePagePreferences prefs = getDefaultPrefs();
    final PreparedPdfDocument result = preparator.preparePdfDocument(
        loadContents("pdf/sample-0-signature.pdf"), prefs, this.configStateless, null, null);

    Assertions.assertNotNull(result.getUpdatedPdfDocument());

    final PDDocument doc = PDDocumentUtils.load(Base64.getDecoder().decode(result.getUpdatedPdfDocument()));
    Assertions.assertEquals(2, doc.getNumberOfPages());
    PDDocumentUtils.close(doc);

    Assertions.assertEquals("stateless-policy", result.getPolicy());
    final VisiblePdfSignatureRequirement reqs = result.getVisiblePdfSignatureRequirement();
    Assertions.assertEquals("default-template", reqs.getTemplateImageRef());
    Assertions.assertEquals(2, reqs.getPage().intValue());
    Assertions.assertEquals(xPosition, reqs.getXPosition().intValue());
    Assertions.assertEquals(yPosition, reqs.getYPosition().intValue());
    Assertions.assertEquals(scale, reqs.getScale().intValue());
    Assertions.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getFieldValues(), reqs.getFieldValues());
    Assertions.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().size(),
        reqs.getSignerName().getSignerAttributes().size());
    Assertions.assertEquals(
        prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().get(0).getName(),
        reqs.getSignerName().getSignerAttributes().get(0).getName());
    Assertions.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getFormatting(),
        reqs.getSignerName()
            .getFormatting());
  }

  @Test
  public void testInsertPageReturnReferenceDeprecated() throws Exception {

    final DocumentCache docCache = new InMemoryDocumentCache();

    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    preparator.setDocumentCache(docCache);

    final PdfSignaturePagePreferences prefs = getDefaultPrefs();
    prefs.setReturnDocumentReference(true);
    final PreparedPdfDocument result = preparator.preparePdfDocument(
        loadContents("pdf/sample-0-signature.pdf"), prefs, this.configStateful, null, null);

    Assertions.assertNull(result.getUpdatedPdfDocument());
    Assertions.assertNotNull(result.getPdfDocumentReference());
    final String updatedDocument = docCache.get(result.getPdfDocumentReference(), null);

    final PDDocument doc = PDDocumentUtils.load(Base64.getDecoder().decode(updatedDocument));
    Assertions.assertEquals(2, doc.getNumberOfPages());
    PDDocumentUtils.close(doc);

    Assertions.assertEquals("stateful-policy", result.getPolicy());
    final VisiblePdfSignatureRequirement reqs = result.getVisiblePdfSignatureRequirement();
    Assertions.assertEquals("default-template", reqs.getTemplateImageRef());
    Assertions.assertEquals(2, reqs.getPage().intValue());
    Assertions.assertEquals(xPosition, reqs.getXPosition().intValue());
    Assertions.assertEquals(yPosition, reqs.getYPosition().intValue());
    Assertions.assertEquals(scale, reqs.getScale().intValue());
    Assertions.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getFieldValues(), reqs.getFieldValues());
    Assertions.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().size(),
        reqs.getSignerName().getSignerAttributes().size());
    Assertions.assertEquals(
        prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().get(0).getName(),
        reqs.getSignerName().getSignerAttributes().get(0).getName());
    Assertions.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getFormatting(),
        reqs.getSignerName()
            .getFormatting());
  }

  @Test
  public void testInsertPageReturnReference() throws Exception {

    final DocumentCache docCache = new InMemoryDocumentCache();

    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    preparator.setDocumentCache(docCache);

    final PdfSignaturePagePreferences prefs = getDefaultPrefs();
    final PreparedPdfDocument result = preparator.preparePdfDocument(
        loadContents("pdf/sample-0-signature.pdf"), prefs, this.configStateful, null, "caller");

    Assertions.assertNull(result.getUpdatedPdfDocument());
    Assertions.assertNotNull(result.getPdfDocumentReference());
    final String updatedDocument = docCache.get(result.getPdfDocumentReference(), "caller");

    final PDDocument doc = PDDocumentUtils.load(Base64.getDecoder().decode(updatedDocument));
    Assertions.assertEquals(2, doc.getNumberOfPages());
    PDDocumentUtils.close(doc);

    Assertions.assertEquals("stateful-policy", result.getPolicy());
    final VisiblePdfSignatureRequirement reqs = result.getVisiblePdfSignatureRequirement();
    Assertions.assertEquals("default-template", reqs.getTemplateImageRef());
    Assertions.assertEquals(2, reqs.getPage().intValue());
    Assertions.assertEquals(xPosition, reqs.getXPosition().intValue());
    Assertions.assertEquals(yPosition, reqs.getYPosition().intValue());
    Assertions.assertEquals(scale, reqs.getScale().intValue());
    Assertions.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getFieldValues(), reqs.getFieldValues());
    Assertions.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().size(),
        reqs.getSignerName().getSignerAttributes().size());
    Assertions.assertEquals(
        prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().get(0).getName(),
        reqs.getSignerName().getSignerAttributes().get(0).getName());
    Assertions.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getFormatting(),
        reqs.getSignerName()
            .getFormatting());
  }

  @Test
  public void testNoNewPageUpdatedPos() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    final PdfSignaturePagePreferences prefs = getDefaultPrefs();
    PreparedPdfDocument result = preparator.preparePdfDocument(
        loadContents("pdf/sample-1-signature.pdf"), prefs, this.configStateless, null, null);

    Assertions.assertNull(result.getUpdatedPdfDocument());

    Assertions.assertEquals("stateless-policy", result.getPolicy());
    VisiblePdfSignatureRequirement reqs = result.getVisiblePdfSignatureRequirement();
    Assertions.assertEquals("default-template", reqs.getTemplateImageRef());
    Assertions.assertEquals(2, reqs.getPage().intValue());
    Assertions.assertEquals(xPosition + xIncrement, reqs.getXPosition().intValue());
    Assertions.assertEquals(yPosition, reqs.getYPosition().intValue());
    Assertions.assertEquals(scale, reqs.getScale().intValue());
    Assertions.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getFieldValues(), reqs.getFieldValues());
    Assertions.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().size(),
        reqs.getSignerName().getSignerAttributes().size());
    Assertions.assertEquals(
        prefs.getVisiblePdfSignatureUserInformation().getSignerName().getSignerAttributes().get(0).getName(),
        reqs.getSignerName().getSignerAttributes().get(0).getName());
    Assertions.assertEquals(prefs.getVisiblePdfSignatureUserInformation().getSignerName().getFormatting(),
        reqs.getSignerName()
            .getFormatting());

    result = preparator.preparePdfDocument(
        loadContents("pdf/sample-2-signatures.pdf"), prefs, this.configStateless, null, null);

    Assertions.assertNull(result.getUpdatedPdfDocument());

    reqs = result.getVisiblePdfSignatureRequirement();
    Assertions.assertEquals(2, reqs.getPage().intValue());
    Assertions.assertEquals(xPosition, reqs.getXPosition().intValue());
    Assertions.assertEquals(yPosition + yIncrement, reqs.getYPosition().intValue());

    result = preparator.preparePdfDocument(
        loadContents("pdf/sample-3-signatures.pdf"), prefs, this.configStateless, null, null);

    reqs = result.getVisiblePdfSignatureRequirement();
    Assertions.assertEquals(xPosition + xIncrement, reqs.getXPosition().intValue());
    Assertions.assertEquals(yPosition + yIncrement, reqs.getYPosition().intValue());

    result = preparator.preparePdfDocument(
        loadContents("pdf/sample-4-signatures.pdf"), prefs, this.configStateless, null, null);

    reqs = result.getVisiblePdfSignatureRequirement();
    Assertions.assertEquals(xPosition, reqs.getXPosition().intValue());
    Assertions.assertEquals(yPosition + 2 * yIncrement, reqs.getYPosition().intValue());

    result = preparator.preparePdfDocument(
        loadContents("pdf/sample-5-signatures.pdf"), prefs, this.configStateless, null, null);

    reqs = result.getVisiblePdfSignatureRequirement();
    Assertions.assertEquals(xPosition + xIncrement, reqs.getXPosition().intValue());
    Assertions.assertEquals(yPosition + 2 * yIncrement, reqs.getYPosition().intValue());

    result = preparator.preparePdfDocument(
        loadContents("pdf/sample-6-signatures.pdf"), prefs, this.configStateless, null, null);

    reqs = result.getVisiblePdfSignatureRequirement();
    Assertions.assertEquals(xPosition, reqs.getXPosition().intValue());
    Assertions.assertEquals(yPosition + 3 * yIncrement, reqs.getYPosition().intValue());

    result = preparator.preparePdfDocument(
        loadContents("pdf/sample-7-signatures.pdf"), prefs, this.configStateless, null, null);

    reqs = result.getVisiblePdfSignatureRequirement();
    Assertions.assertEquals(xPosition + xIncrement, reqs.getXPosition().intValue());
    Assertions.assertEquals(yPosition + 3 * yIncrement, reqs.getYPosition().intValue());
  }

  @Test
  public void testNoNewPageUpdatedPosReference() throws Exception {
    final DocumentCache docCache = new InMemoryDocumentCache();

    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    preparator.setDocumentCache(docCache);

    final PdfSignaturePagePreferences prefs = getDefaultPrefs();
    final byte[] uploadedDocument = loadContents("pdf/sample-1-signature.pdf");
    final PreparedPdfDocument result = preparator.preparePdfDocument(
        uploadedDocument, prefs, this.configStateful, null, "userid");

    Assertions.assertNull(result.getUpdatedPdfDocument());
    Assertions.assertNotNull(result.getPdfDocumentReference());
    try {
      docCache.get(result.getPdfDocumentReference(), null);
      Assertions.fail("Expected NoAccessException");
    }
    catch (final NoAccessException ignored) {
    }
    try {
      docCache.get(result.getPdfDocumentReference(), "otheruser");
      Assertions.fail("Expected NoAccessException");
    }
    catch (final NoAccessException ignored) {
    }
    final String cachedDocument = docCache.get(result.getPdfDocumentReference(), "userid");
    final byte[] cachedDocumentBytes = Base64.getDecoder().decode(cachedDocument);
    Assertions.assertArrayEquals(uploadedDocument, cachedDocumentBytes);

    Assertions.assertEquals("stateful-policy", result.getPolicy());
  }

  @Test
  void testPdfWithFormAndEncryptionDictionary() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();

    final DefaultIntegrationServiceConfiguration config = this.configStateful.toBuilder()
        .pdfPrepareSettings(PdfPrepareSettings.builder()
            .allowFlattenAcroForms(true)
            .allowRemoveEncryptionDictionary(true)
            .build())
        .build();

    final PreparedPdfDocument result = preparator.preparePdfDocument(
        loadContents("pdf/open-form-with-encryption-dict.pdf"), getDefaultPrefs(), config, null, null);

    Assertions.assertNotNull(result.getUpdatedPdfDocument());
    Assertions.assertTrue(
        result.getPrepareReport().getActions().contains(PdfPrepareReport.PrepareActions.REMOVED_ENCRYPTION_DICTIONARY));
    Assertions.assertTrue(
        result.getPrepareReport().getActions().contains(PdfPrepareReport.PrepareActions.FLATTENED_ACROFORM));

    try (final PDDocument doc = PDDocumentUtils.load(Base64.getDecoder().decode(result.getUpdatedPdfDocument()))) {
      Assertions.assertNull(doc.getDocumentCatalog().getAcroForm());
      Assertions.assertNull(doc.getEncryption());
      Assertions.assertEquals(2, doc.getPages().getCount());
    }
  }

  void testPdfWithFormAndEncryptionDictionaryNoFix() {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();

    final DefaultIntegrationServiceConfiguration config = DefaultIntegrationServiceConfiguration.builder()
        .policy("test")
        .pdfPrepareSettings(PdfPrepareSettings.builder()
            .allowFlattenAcroForms(false)
            .allowRemoveEncryptionDictionary(true)
            .build())
        .build();

    Assertions.assertThrows(PdfContainsAcroformException.class, () ->
        preparator.preparePdfDocument(
            loadContents("pdf/open-form-with-encryption-dict.pdf"), null, config, null, null));

    final DefaultIntegrationServiceConfiguration config2 = DefaultIntegrationServiceConfiguration.builder()
        .policy("test")
        .pdfPrepareSettings(PdfPrepareSettings.builder()
            .allowFlattenAcroForms(true)
            .allowRemoveEncryptionDictionary(false)
            .build())
        .build();

    Assertions.assertThrows(PdfContainsEncryptionDictionaryException.class, () ->
        preparator.preparePdfDocument(
            loadContents("pdf/open-form-with-encryption-dict.pdf"), null, config2, null, null));

  }

  @Test
  void testPdfAInconsistency() {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();

    final DefaultIntegrationServiceConfiguration config = this.configStateful.toBuilder()
        .pdfPrepareSettings(PdfPrepareSettings.builder()
            .enforcePdfaConsistency(true)
            .build())
        .build();

    Assertions.assertThrows(PdfAConsistencyCheckException.class, () -> preparator.preparePdfDocument(
        loadContents("pdfa/Test_pdfa.pdf"), getDefaultPrefs(), config, null, null));
  }

  @Test
  void testPdfAInconsistencyWarning() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();

    final DefaultIntegrationServiceConfiguration config = this.configStateful.toBuilder()
        .pdfPrepareSettings(PdfPrepareSettings.builder()
            .enforcePdfaConsistency(false)
            .build())
        .build();

    final PreparedPdfDocument result = preparator.preparePdfDocument(
        loadContents("pdfa/Test_pdfa.pdf"), getDefaultPrefs(), config, null, null);

    Assertions.assertNotNull(result.getUpdatedPdfDocument());
    Assertions.assertTrue(
        result.getPrepareReport().getWarnings().contains(PdfPrepareReport.PrepareWarnings.PDFA_INCONSISTENCY));

    try (final PDDocument doc = PDDocumentUtils.load(Base64.getDecoder().decode(result.getUpdatedPdfDocument()))) {
      Assertions.assertEquals(2, doc.getPages().getCount());
    }
  }

  public static PdfSignaturePagePreferences getDefaultPrefs() {
    return PdfSignaturePagePreferences.builder()
        .signaturePageReference("default-sign-page")
        .visiblePdfSignatureUserInformation(VisiblePdfSignatureUserInformation.toBuilder()
            .signerName(SignerName.builder()
                .signerAttribute(
                    SignerIdentityAttribute.createBuilder().name("urn:oid:2.16.840.1.113730.3.1.241").build())
                .build())
            .fieldValue("IDP", "eduID Sverige")
            .build())
        .failWhenSignPageFull(false)
        .build();
  }

  public static byte[] loadContents(final String resource) throws IOException {
    return IOUtils.toByteArray((new ClassPathResource(resource)).getInputStream());
  }

}
