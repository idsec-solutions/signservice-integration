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
package se.idsec.signservice.integration.document.pdf.visiblesig;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.commons.lang.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureRequirement;
import se.idsec.signservice.security.sign.pdf.document.VisibleSigImage;

/**
 * Factory for creating instances of {@link VisibleSigImage} as input to a PDF sign process.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class VisibleSigImageFactory {

  /** List of available PDF signature image templates. */
  private final List<? extends PdfSignatureImageTemplate> pdfSignatureImageTemplates;

  /**
   * Constructor.
   *
   * @param pdfSignatureImageTemplates
   *          list of available PDF signature image templates
   */
  public VisibleSigImageFactory(final List<? extends PdfSignatureImageTemplate> pdfSignatureImageTemplates) {
    this.pdfSignatureImageTemplates = pdfSignatureImageTemplates;
  }

  /**
   * Obtain an instance of {@link VisibleSigImage}.
   * 
   * @param visiblePdfSignatureRequirement
   *          the requirements for a visible sign image
   * @param signerAttributes
   *          the list of attributes that shall be used to form the signers name in the sign image
   * @return a VisibleSigImage
   * @throws VisiblePdfSignatureRequirementException
   *           for errors
   */
  public VisibleSigImage getVisibleSignImage(
      final VisiblePdfSignatureRequirement visiblePdfSignatureRequirement,
      final List<SignerIdentityAttributeValue> signerAttributes) throws VisiblePdfSignatureRequirementException {

    final PdfSignatureImageTemplate template = this.getTemplate(visiblePdfSignatureRequirement.getTemplateImageRef());

    final Map<String, String> imageParams = new HashMap<>();
    if (visiblePdfSignatureRequirement.getFieldValues() != null) {
      imageParams.putAll(visiblePdfSignatureRequirement.getFieldValues());
    }

    final VisiblePdfSignatureRequirement.SignerName signerName = visiblePdfSignatureRequirement.getSignerName();
    if (signerName != null && template.isIncludeSignerName()) {
      final List<SignerIdentityAttribute> signerAttributeNames = signerName.getSignerAttributes();

      // Make sure that all attribute names listed in the requirement are available in the
      // signer attributes.
      //
      if (signerAttributes == null || signerAttributes.isEmpty()) {
        final String msg = String.format("The VisiblePdfSignatureRequirement for template '%s' requires "
            + "signer name info, but no requested signer attributes are available", template.getReference());
        throw new VisiblePdfSignatureRequirementException(msg);
      }
      for (SignerIdentityAttribute attrName : signerAttributeNames) {
        if (!signerAttributes.stream().filter(a -> Objects.equals(a.getName(), attrName.getName())).findFirst().isPresent()) {
          final String msg = String.format("The VisiblePdfSignatureRequirement for template '%s' requires "
              + "signer name info for attribute '%s', but this has not been provied among the requested signer attributes",
            template.getReference(), attrName.getName());
          throw new VisiblePdfSignatureRequirementException(msg);
        }
      }
      final String formatString = signerName.getFormatting();
      String name = formatString;

      if (StringUtils.isBlank(name)) {
        // If we don't have a format string we just concatenate all values in order ...
        name = String.join(" ", signerAttributeNames.stream()
          .map(a -> getAttributeValue(a.getName(), signerAttributes))
          .collect(Collectors.toList()));
      }
      else {
        // Otherwise format the signer name according to format string ...
        //
        for (int i = 0; i < signerAttributeNames.size(); i++) {
          name = name.replaceAll("%" + String.valueOf(i + 1),
            getAttributeValue(signerAttributeNames.get(i).getName(), signerAttributes));
        }
      }
      imageParams.put(PdfSignatureImageTemplate.SIGNER_NAME_FIELD_NAME, name);
    }

    return VisibleSigImage.builder()
      .page(visiblePdfSignatureRequirement.getPage())
      .xOffset(visiblePdfSignatureRequirement.getXPosition())
      .yOffset(visiblePdfSignatureRequirement.getYPosition())
      .zoomPercent(visiblePdfSignatureRequirement.getScale())
      .personalizationParams(imageParams)
      .pixelImageWidth(template.getWidth())
      .pixelImageHeight(template.getHeight())
      .includeDate(template.isIncludeSigningTime())
      .svgImage(template.getImage())
      .build();
  }

  /**
   * Obtain an instance of {@link VisibleSigImage} and return its encoding.
   * 
   * @param visiblePdfSignatureRequirement
   *          the requirements for a visible sign image
   * @param signerAttributes
   *          the list of attributes that shall be used to form the signers name in the sign image
   * @return the encoding of a VisibleSigImage
   * @throws VisiblePdfSignatureRequirementException
   *           for errors
   */
  public String getEncodedVisibleSignImage(
      final VisiblePdfSignatureRequirement visiblePdfSignatureRequirement,
      final List<SignerIdentityAttributeValue> signerAttributes) throws VisiblePdfSignatureRequirementException {

    try {
      return VisibleSigImageSerializer.serializeVisibleSignatureObject(
        this.getVisibleSignImage(visiblePdfSignatureRequirement, signerAttributes));
    }
    catch (IOException e) {
      final String msg = String.format("Failed to serialize the PDF signature image - %s", e.getMessage());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new VisiblePdfSignatureRequirementException(msg, e);
    }
  }

  /**
   * Gets a PDF signature image template based on its reference.
   * 
   * @param reference
   *          the reference
   * @return a PdfSignatureImageTemplate object
   */
  PdfSignatureImageTemplate getTemplate(final String reference) {
    return this.pdfSignatureImageTemplates.stream()
      .filter(t -> t.getReference().equals(reference))
      .findFirst()
      // We have already asserted (in the validator) that the template exists ...
      .orElseThrow(() -> new RuntimeException("Internal error - PDF Image template not found - " + reference));
  }

  private static String getAttributeValue(final String attributeName, List<SignerIdentityAttributeValue> signerAttributes) {
    return signerAttributes.stream()
      .filter(a -> attributeName.equals(a.getName()))
      .map(SignerIdentityAttributeValue::getValue)
      .findFirst()
      // We have already asserted that the attribute name is there ...
      .orElseThrow(() -> new RuntimeException("Internal error - missing attribute"));
  }

}
