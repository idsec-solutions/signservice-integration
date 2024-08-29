package se.idsec.signservice.integration.document.pdf;

import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.FileResource;
import se.idsec.signservice.integration.document.pdf.signpage.DefaultPdfSignaturePagePreparator;
import se.idsec.signservice.integration.document.pdf.signpage.DefaultPdfSignaturePagePreparatorTest;
import se.idsec.signservice.integration.document.pdf.utils.PDDocumentUtils;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TbsPdfDocumentIssueHandler}
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
class TbsPdfDocumentIssueHandlerTest {

  private DefaultIntegrationServiceConfiguration configStateless;

  private static final int xPosition = 37;
  private static final int xIncrement = 268;
  private static final int yPosition = 165;
  private static final int yIncrement = 105;
  private static final int scale = -74;

  public TbsPdfDocumentIssueHandlerTest() {
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
        .imagePlacementConfiguration(PdfSignaturePage.PdfSignatureImagePlacementConfiguration.builder()
          .xPosition(xPosition)
          .xIncrement(xIncrement)
          .yPosition(yPosition)
          .yIncrement(yIncrement)
          .scale(scale)
          .build())
        .build())
      .stateless(true)
      .build();

  }

  @Test
  void testPdfWithFormAndEncryptionDictionary() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    preparator.setFlattenAcroFroms(true);
    preparator.setRemoveEncryptionDictionary(true);
    byte[] pdfBytes = DefaultPdfSignaturePagePreparatorTest.loadContents("pdf/open-form-with-encryption-dict.pdf");
    TbsPdfDocumentIssueHandler issueHandler = new TbsPdfDocumentIssueHandler();
    List<PdfDocumentIssue> pdfDocumentIssues = issueHandler.identifyFixableIssues(pdfBytes);
    assertTrue(pdfDocumentIssues.contains(PdfDocumentIssue.ACROFORM_IN_UNSIGNED_PDF));
    assertTrue(pdfDocumentIssues.contains(PdfDocumentIssue.ENCRYPTION_DICTIONARY));

    final PdfSignaturePagePreferences prefs = DefaultPdfSignaturePagePreparatorTest.getDefaultPrefs();
    final PreparedPdfDocument result = preparator.preparePdfSignaturePage(
      DefaultPdfSignaturePagePreparatorTest.loadContents("pdf/open-form-with-encryption-dict.pdf"), prefs, this.configStateless);

    Assertions.assertNotNull(result.getUpdatedPdfDocument());

    try (
      final PDDocument doc = PDDocumentUtils.load(Base64.getDecoder().decode(result.getUpdatedPdfDocument()));
    ) {
      Assertions.assertNull(doc.getDocumentCatalog().getAcroForm());
      Assertions.assertNull(doc.getEncryption());
      Assertions.assertEquals(2, doc.getPages().getCount());
    }

  }

  @Test
  void testFixInPreProcessBytes() throws Exception {
    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    preparator.setFlattenAcroFroms(false);
    preparator.setRemoveEncryptionDictionary(false);
    byte[] pdfBytes = DefaultPdfSignaturePagePreparatorTest.loadContents("pdf/open-form-with-encryption-dict.pdf");
    TbsPdfDocumentIssueHandler issueHandler = new TbsPdfDocumentIssueHandler();
    List<PdfDocumentIssue> pdfDocumentIssues = issueHandler.identifyFixableIssues(pdfBytes);
    assertTrue(pdfDocumentIssues.contains(PdfDocumentIssue.ACROFORM_IN_UNSIGNED_PDF));
    assertTrue(pdfDocumentIssues.contains(PdfDocumentIssue.ENCRYPTION_DICTIONARY));
    byte[] fixedPdf = issueHandler.fixIssues(pdfBytes, pdfDocumentIssues);

    final PdfSignaturePagePreferences prefs = DefaultPdfSignaturePagePreparatorTest.getDefaultPrefs();
    final PreparedPdfDocument result = preparator.preparePdfSignaturePage(fixedPdf, prefs, this.configStateless);

    Assertions.assertNotNull(result.getUpdatedPdfDocument());

    try (
      final PDDocument doc = PDDocumentUtils.load(Base64.getDecoder().decode(result.getUpdatedPdfDocument()));
    ) {
      Assertions.assertNull(doc.getDocumentCatalog().getAcroForm());
      Assertions.assertNull(doc.getEncryption());
      Assertions.assertEquals(2, doc.getPages().getCount());
    }
  }

  @Test
  void testFixInPreProcessDoc() throws Exception {
    byte[] pdfBytes = DefaultPdfSignaturePagePreparatorTest.loadContents("pdf/open-form-with-encryption-dict.pdf");
    final PDDocument pdfDoc = PDDocumentUtils.load(pdfBytes);
    TbsPdfDocumentIssueHandler issueHandler = new TbsPdfDocumentIssueHandler();
    List<PdfDocumentIssue> pdfDocumentIssues = issueHandler.identifyFixableIssues(pdfDoc);
    assertTrue(pdfDocumentIssues.contains(PdfDocumentIssue.ACROFORM_IN_UNSIGNED_PDF));
    assertTrue(pdfDocumentIssues.contains(PdfDocumentIssue.ENCRYPTION_DICTIONARY));
    issueHandler.fixIssues(pdfDoc, pdfDocumentIssues);

    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    final PdfSignaturePagePreferences prefs = DefaultPdfSignaturePagePreparatorTest.getDefaultPrefs();
    final PreparedPdfDocument result = preparator.preparePdfSignaturePage(PDDocumentUtils.toBytes(pdfDoc), prefs, this.configStateless);

    Assertions.assertNotNull(result.getUpdatedPdfDocument());

    try (
      final PDDocument doc = PDDocumentUtils.load(Base64.getDecoder().decode(result.getUpdatedPdfDocument()));
    ) {
      Assertions.assertNull(doc.getDocumentCatalog().getAcroForm());
      Assertions.assertNull(doc.getEncryption());
      Assertions.assertEquals(2, doc.getPages().getCount());
    }
  }

  @Test
  void testNoFixAcroform() throws Exception {
    byte[] pdfBytes = DefaultPdfSignaturePagePreparatorTest.loadContents("pdf/open-form-with-encryption-dict.pdf");
    TbsPdfDocumentIssueHandler issueHandler = new TbsPdfDocumentIssueHandler();
    List<PdfDocumentIssue> pdfDocumentIssues = issueHandler.identifyFixableIssues(pdfBytes);
    assertTrue(pdfDocumentIssues.contains(PdfDocumentIssue.ACROFORM_IN_UNSIGNED_PDF));
    assertTrue(pdfDocumentIssues.contains(PdfDocumentIssue.ENCRYPTION_DICTIONARY));
    byte[] notCompletelyFixed = issueHandler.fixIssues(pdfBytes, List.of(PdfDocumentIssue.ENCRYPTION_DICTIONARY));

    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    final PdfSignaturePagePreferences prefs = DefaultPdfSignaturePagePreparatorTest.getDefaultPrefs();
    final PreparedPdfDocument result = preparator.preparePdfSignaturePage(notCompletelyFixed, prefs, this.configStateless);

    try (
      final PDDocument doc = PDDocumentUtils.load(Base64.getDecoder().decode(result.getUpdatedPdfDocument()));
    ) {
      assertEquals(1, doc.getDocumentCatalog().getAcroForm().getFields().size());
      Assertions.assertNull(doc.getEncryption());
      Assertions.assertEquals(2, doc.getPages().getCount());
    }

  }

  @Test
  void testNoFixEncryption() throws Exception {
    byte[] pdfBytes = DefaultPdfSignaturePagePreparatorTest.loadContents("pdf/open-form-with-encryption-dict.pdf");
    final PDDocument pdfDoc = PDDocumentUtils.load(pdfBytes);
    TbsPdfDocumentIssueHandler issueHandler = new TbsPdfDocumentIssueHandler();
    List<PdfDocumentIssue> pdfDocumentIssues = issueHandler.identifyFixableIssues(pdfDoc);
    assertTrue(pdfDocumentIssues.contains(PdfDocumentIssue.ACROFORM_IN_UNSIGNED_PDF));
    assertTrue(pdfDocumentIssues.contains(PdfDocumentIssue.ENCRYPTION_DICTIONARY));
    issueHandler.fixIssues(pdfDoc, List.of(PdfDocumentIssue.ACROFORM_IN_UNSIGNED_PDF));

    final DefaultPdfSignaturePagePreparator preparator = new DefaultPdfSignaturePagePreparator();
    final PdfSignaturePagePreferences prefs = DefaultPdfSignaturePagePreparatorTest.getDefaultPrefs();

    Exception exception = assertThrows(IllegalStateException.class, () -> {
      preparator.preparePdfSignaturePage(PDDocumentUtils.toBytes(pdfDoc), prefs, this.configStateless);
    });
    log.info("Exception: {}", exception.toString());
  }

}

