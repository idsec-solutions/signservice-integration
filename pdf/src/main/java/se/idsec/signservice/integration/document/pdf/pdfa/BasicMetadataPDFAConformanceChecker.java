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
package se.idsec.signservice.integration.document.pdf.pdfa;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import se.idsec.signservice.integration.document.pdf.PdfAConsistencyCheckException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Basic PDF/A conformance checker based on PDF metadata declaration inspection.
 * <p>
 * This conformance checker only checks if the PDF document metadata claims that the document conforms to the PDF/A
 * standard. This checker does not validate if the present document actually is compliant with PDF/A.
 * </p>
 * <p>
 * For rules on how to detect PDF/A compliance declaration in metadata, see:
 * https://www.pdfa.org/wp-content/uploads/2011/08/tn0001_pdfa-1_and_namespaces_2008-03-182.pdf
 * </p>
 * <p>
 * Note that this conformance checker does not support the earlier, but false PDF/A declaration namespaces such as
 * ("http://www.aiim.org/pdfa/ns/id.html" and "http://www.aiim.org/pdfa/ns/id"). However, it is possible to set the
 * namespace identifier to a custom value to alter the behavior of this conformance checker.
 * </p>
 */
@Slf4j
public class BasicMetadataPDFAConformanceChecker implements PDFAConformanceChecker {

  /** Name space identifier for the descriptions element in PDF metadata */
  public static final String DESCRITPION_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";

  /** Description element name */
  public static final String DESCRIPTION_ELEMENT_NAME = "Description";

  /** PDF/A part element name */
  public static final String PART_ELEMENT_NAME = "part";

  /** PDF/A conformance element name */
  public static final String CONFORMANCE_ELEMENT_NAME = "conformance";

  /** Name space identifier for PDF/A declarations in PDF metadata */
  @Setter
  public String pdfaIdNs = "http://www.aiim.org/pdfa/ns/id/";

  /** List of supported part values in PDF/A declarations */
  @Setter
  private List<String> supportedPartValues = List.of("1", "2");

  /** List of supported conformance values in PDF/A declarations */
  @Setter
  private List<String> supportedConformanceValues = List.of("B");

  /**
   * Constructor
   */
  public BasicMetadataPDFAConformanceChecker() {
  }

  /** {@inheritDoc} */
  @Override
  public PDFAStatus checkPDFAConformance(final PDMetadata metadata) {
    if (metadata == null) {
      return PDFAStatus.builder()
          .valid(false)
          .build();
    }
    return this.checkPDFADeclaration(metadata.getCOSObject().toTextString());
  }

  /** {@inheritDoc} */
  @Override
  public boolean isPDFAConsistent(final PDDocument tbsDoc, final PDDocument signPage) {
    final PDFAStatus tbsDocPdfaStatus = this.checkPDFAConformance(tbsDoc.getDocumentCatalog().getMetadata());
    final PDFAStatus signPagePdfaStatus = this.checkPDFAConformance(signPage.getDocumentCatalog().getMetadata());
    if (tbsDocPdfaStatus.isValid() && !signPagePdfaStatus.isValid()) {
      log.info("The document to be sign is PDF/A but the added "
          + "sign page is not PDF/A. This will break PDF/A conformance of the document to be signed");
      return false;
    }
    else {
      return true;
    }
  }

  /** {@inheritDoc} */
  @Override
  public void assertPDFAConsistency(final PDDocument tbsDoc, final PDDocument signPage)
      throws PdfAConsistencyCheckException {
    if (!this.isPDFAConsistent(tbsDoc, signPage)) {
      throw new PdfAConsistencyCheckException("The document to be sign is PDF/A but the added "
          + "sign page is not PDF/A. This will break PDF/A conformance of the document to be signed");
    }
  }

  /**
   * Examines PDF document metadata for declarations that this PDF is compliant with the PDF/A profile
   *
   * @param metadataStr PDF document metadata
   * @return PDF/A declaration data
   */
  public PDFAStatus checkPDFADeclaration(final String metadataStr) {
    if (StringUtils.isBlank(metadataStr)) {
      return PDFAStatus.builder()
          .valid(false)
          .build();
    }

    try {
      // Get elementNames
      final String descElmName = this.getFullElementName(DESCRITPION_NS, DESCRIPTION_ELEMENT_NAME, metadataStr);
      final String pdfaPartElmName = this.getFullElementName(this.pdfaIdNs, PART_ELEMENT_NAME, metadataStr);
      final String pdfaConformanceElmName =
          this.getFullElementName(this.pdfaIdNs, CONFORMANCE_ELEMENT_NAME, metadataStr);

      // Get the description content
      final ElementData descritpion = this.getFirstContent(descElmName, metadataStr);
      if (descritpion == null) {
        return PDFAStatus.builder()
            .valid(false)
            .build();
      }

      final String partVal = this.getAttributeOrElementValue(pdfaPartElmName, descritpion);
      final String conformanceVal = this.getAttributeOrElementValue(pdfaConformanceElmName, descritpion);

      if (partVal == null || conformanceVal == null) {
        log.debug("No valid PDF/A conformance declaration found");
        return PDFAStatus.builder()
            .part(partVal)
            .conformance(conformanceVal)
            .valid(false)
            .build();
      }

      if (this.supportedPartValues.contains(partVal) && this.supportedConformanceValues.contains(conformanceVal)) {
        log.debug("Found supported PDF/A conformance declaration in metadata");
        return PDFAStatus.builder()
            .part(partVal)
            .conformance(conformanceVal)
            .valid(true)
            .build();
      }
      else {
        log.debug("Found invalid PDF/A conformance declaration");
        return PDFAStatus.builder()
            .part(partVal)
            .conformance(conformanceVal)
            .valid(false)
            .build();
      }

    }
    catch (final Exception ex) {
      log.debug("PDF/A conformance test caused exception: {}", ex.toString());
      return PDFAStatus.builder()
          .valid(false)
          .build();
    }
  }

  private String getAttributeOrElementValue(final String targetName, final ElementData element) {
    if (element == null) {
      return null;
    }
    if (element.getAttributeMap().containsKey(targetName)) {
      return element.getAttributeMap().get(targetName);
    }
    final ElementData targetElement = this.getFirstContent(targetName, element.getContent());
    return targetElement == null ? null : targetElement.getContent();
  }

  private String getFullElementName(final String nsUri, final String name, final String document) {
    final String nsId = this.getNsId(nsUri, document);
    return nsId != null
        ? nsId + ":" + name
        : name;
  }

  private String getNsId(final String nsUri, final String xmlString) {

    final Pattern pattern = Pattern.compile("xmlns:\\w*\\s*=\\s*\"" + nsUri.replaceAll("/", "\\\\/") + "\"");
    final Matcher matcher = pattern.matcher(xmlString);
    if (matcher.find()) {
      final String ns = matcher.group(0);
      return ns.substring(6, ns.indexOf("=")).trim();
    }
    return null;
  }

  private ElementData getFirstContent(final String fullElementName, final String data) {
    final List<ElementData> contentList = this.getContent(fullElementName, data);
    return contentList.isEmpty() ? null : contentList.get(0);
  }

  private List<ElementData> getContent(final String fullElementName, final String dataFragment) {

    final Pattern pattern = Pattern.compile("<" + fullElementName + "[\\S\\s]+" + ("</" + fullElementName + ">"));
    final Matcher matcher = pattern.matcher(dataFragment);

    final List<ElementData> elementDataList = new ArrayList<>();
    while (matcher.find()) {
      final String fullElement = matcher.group(0);
      final ElementData elementData = ElementData.builder()
          .element(fullElement)
          .content(fullElement.substring(
              fullElement.indexOf(">") + 1,
              fullElement.lastIndexOf("</" + fullElementName + ">")))
          .attributeMap(this.getAttributeMap(fullElementName, fullElement))
          .build();
      elementDataList.add(elementData);
    }
    return elementDataList;
  }

  private Map<String, String> getAttributeMap(final String fullElementName, final String fullElement) {
    final Map<String, String> attributeMap = new HashMap<>();

    final String attributeDataStr = fullElement.substring(
        fullElementName.length() + 1,
        fullElement.indexOf(">")).trim();
    if (!attributeDataStr.isEmpty()) {
      final String[] attributes = attributeDataStr.split("\\s+");
      for (final String attribute : attributes) {
        if (attribute.contains("=")) {
          final String[] attributeParts = attribute.split("=");
          final String attrName = attributeParts[0];
          final String attrVal = attributeParts[1].substring(1, attributeParts[1].length() - 1);
          attributeMap.put(attrName, attrVal);
        }
      }
    }
    return attributeMap;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  public static class ElementData {

    private String element;
    private Map<String, String> attributeMap;
    private String content;
  }

}
