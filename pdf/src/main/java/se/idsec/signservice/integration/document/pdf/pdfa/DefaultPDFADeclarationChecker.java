/*
 * Copyright 2019-2022 IDsec Solutions AB
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
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.document.DocumentProcessingException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Testing PDF metadata for PDF/A conformance declaration
 *
 * <p>
 *   For rules on how to detect PDF/A compliance declaration, see:
 *   https://www.pdfa.org/wp-content/uploads/2011/08/tn0001_pdfa-1_and_namespaces_2008-03-182.pdf
 * </p>
 */
@Slf4j
public class DefaultPDFADeclarationChecker implements PDFADeclarationChecker {

  /** Name space identifier for PDFA declarations in PDF metadata */
  public static final String PDF_ID_NS = "http://www.aiim.org/pdfa/ns/id/";

  /** Name space identifier for the descriptions element in PDF metadata */
  public static final String DESCRITPION_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";

  /** Description element name */
  public static final String DESCRIPTION_ELEMENT_NAME = "Description";

  /** PDF/A part element name */
  public static final String PART_ELEMENT_NAME = "part";

  /** PDF/A conformance element name */
  public static final String CONFORMANCE_ELEMENT_NAME = "conformance";

  /** List of supported part values in PDF/A declarations */
  @Setter private List<String> supportedPartValues = List.of("1", "2");

  /** List of supported conformance values in PDF/A declarations */
  @Setter private List<String> supportedConformanceValues = List.of("B");

  /**
   * Constructor
   */
  public DefaultPDFADeclarationChecker() {
  }

  /** {@inheritDoc} */
  @Override
  public PDFAStatus checkPDFADeclaration(final PDMetadata metadata) {
    if (metadata == null){
      return PDFAStatus.builder()
        .valid(false)
        .build();
    }
    return checkPDFADeclaration(metadata.getCOSObject().toTextString());
  }

  /**
   * Check PDF/A consistency between the main document to be signed and a sign page added to the main document
   *
   * @param tbsDoc the pdf document to be signed
   * @param signPage the sign page added to the document to be signed
   * @throws DocumentProcessingException if the main document is PDF/A and the added sign page is not
   */
  @Override public void checkPDFAConsistency(final PDDocument tbsDoc, final PDDocument signPage)
    throws DocumentProcessingException {
    final PDFAStatus tbsDocPdfaStatus = checkPDFADeclaration(
      tbsDoc.getDocumentCatalog().getMetadata());
    final PDFAStatus signPagePdfaStatus = checkPDFADeclaration(
      signPage.getDocumentCatalog().getMetadata());
    if (tbsDocPdfaStatus.isValid() && !signPagePdfaStatus.isValid()){
      throw new DocumentProcessingException(new ErrorCode.Code("pdf"),"The document to be sign is PDF/A but the added "
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
      final String descElmName = getFullElementName(DESCRITPION_NS, DESCRIPTION_ELEMENT_NAME, metadataStr);
      final String pdfaPartElmName = getFullElementName(PDF_ID_NS, PART_ELEMENT_NAME, metadataStr);
      final String pdfaConformanceElmName = getFullElementName(PDF_ID_NS, CONFORMANCE_ELEMENT_NAME, metadataStr);

      // Get the description content
      final ElementData descritpion = getFirstContent(descElmName, metadataStr);
      if (descritpion == null) {
        return PDFAStatus.builder()
          .valid(false)
          .build();
      }

      final String partVal = getAttributeOrElementValue(pdfaPartElmName, descritpion);
      final String conformanceVal = getAttributeOrElementValue(pdfaConformanceElmName, descritpion);

      if (partVal == null || conformanceVal == null) {
        log.debug("No valid PDF/A conformance declaration found");
        return PDFAStatus.builder()
          .part(partVal)
          .conformance(conformanceVal)
          .valid(false)
          .build();
      }

      if (supportedPartValues.contains(partVal) && supportedConformanceValues.contains(conformanceVal)){
        log.debug("Found supported PDF/A conformance declaration in metadata");
        return PDFAStatus.builder()
          .part(partVal)
          .conformance(conformanceVal)
          .valid(true)
          .build();
      } else {
        log.debug("Found invalid PDF/A conformance declaration");
        return PDFAStatus.builder()
          .part(partVal)
          .conformance(conformanceVal)
          .valid(false)
          .build();
      }

    } catch (Exception ex) {
      log.debug("PDF/A conformance test caused exception: {}", ex.toString());
      return PDFAStatus.builder()
        .valid(false)
        .build();
    }
  }

  private String getAttributeOrElementValue(final String targetName, final ElementData element) {
    if (element == null){
      return null;
    }
    if (element.getAttributeMap().containsKey(targetName)) {
      return element.getAttributeMap().get(targetName);
    }
    final ElementData targetElement = getFirstContent(targetName, element.getContent());
    return targetElement == null ? null : targetElement.getContent();
  }

  private String getFullElementName(final String nsUri, final String name, final String document) {
    String nsId = getNsId(nsUri, document);
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
    final List<ElementData> contentList = getContent(fullElementName, data);
    return contentList.isEmpty() ? null : contentList.get(0);
  }

  private List<ElementData> getContent(final String fullElementName, final String dataFragment) {

    final Pattern pattern = Pattern.compile("<" + fullElementName + "[\\S\\s]+" + ("</" + fullElementName + ">"));
    final Matcher matcher = pattern.matcher(dataFragment);

    List<ElementData> elementDataList = new ArrayList<>();
    while (matcher.find()) {
      String fullElement = matcher.group(0);
      ElementData elementData = ElementData.builder()
        .element(fullElement)
        .content(fullElement.substring(
          fullElement.indexOf(">") + 1,
          fullElement.lastIndexOf("</" + fullElementName + ">")
        ))
        .attributeMap(getAttributeMap(fullElementName, fullElement))
        .build();
      elementDataList.add(elementData);
    }
    return elementDataList;
  }

  private Map<String, String> getAttributeMap(final String fullElementName, final String fullElement) {
    Map<String, String> attributeMap = new HashMap<>();

    String attributeDataStr = fullElement.substring(
      fullElementName.length() + 1,
      fullElement.indexOf(">")
    ).trim();
    if (attributeDataStr.length() > 0) {
      String[] attributes = attributeDataStr.split("\\s+");
      for (String attribute : attributes) {
        if (attribute.contains("=")) {
          String[] attributeParts = attribute.split("=");
          String attrName = attributeParts[0];
          String attrVal = attributeParts[1].substring(1, attributeParts[1].length() - 1);
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
