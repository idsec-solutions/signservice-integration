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

import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureRequirement;
import se.idsec.signservice.security.sign.pdf.document.VisibleSigImage;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Factory for creating instances of {@link VisibleSigImage} as input to a PDF sign process
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class VisibleSigImageFactory {

  /** List of available PDF signature image templates */
  private List<? extends PdfSignatureImageTemplate> pdfSignatureImageTemplates;

  /**
   * Constructor
   *
   * @param pdfSignatureImageTemplates list of available PDF signature image templates
   */
  public VisibleSigImageFactory(List<? extends PdfSignatureImageTemplate> pdfSignatureImageTemplates) {
    this.pdfSignatureImageTemplates = pdfSignatureImageTemplates;
  }

  /**
   * Obtain an instance of {@link VisibleSigImage}
   * @param visiblePdfSignatureRequirement the requirements for a visible sign image
   * @param signerAttributeList the list of attributes that shall be used to form the signers name in the sign image
   * @return {@link VisibleSigImage} or null if no sign image should be created
   */
  public VisibleSigImage getVisibleSignImage(VisiblePdfSignatureRequirement visiblePdfSignatureRequirement,
    List<SignerIdentityAttributeValue> signerAttributeList) {
    VisiblePdfSignatureRequirement.SignerName signerName = visiblePdfSignatureRequirement.getSignerName();
    List<SignerIdentityAttribute> nameattrList = signerName.getSignerAttributes();
    Map<String, String> imageParams = new HashMap<>(visiblePdfSignatureRequirement.getFieldValues());
    String formatString = signerName.getFormatting();

    if (signerName != null && nameattrList != null && nameattrList.size() > 0 && formatString != null) {
      String name = formatString;
      for (int i = 0; i < nameattrList.size(); i++) {
        String attrName = nameattrList.get(i).getName();
        Optional<SignerIdentityAttributeValue> signerAttr = signerAttributeList.stream()
          .filter(attribute -> attribute.getName().equalsIgnoreCase(attrName))
          .findFirst();
        if (signerAttr.isPresent()) {
          name = name.replaceAll("%" + String.valueOf(i + 1), signerAttr.get().getValue());
        }
        else {
          Logger.getLogger(VisibleSigImageFactory.class.getName())
            .warning("Illegal request for sign image. Required name attributes are not provided");
          return null;
        }
      }
      imageParams.put("signer", name);
    }

    try {
      return getVisibleSignImage(
        visiblePdfSignatureRequirement.getTemplateImageRef(),
        visiblePdfSignatureRequirement.getPage(),
        visiblePdfSignatureRequirement.getXPosition(),
        visiblePdfSignatureRequirement.getYPosition(),
        visiblePdfSignatureRequirement.getScale(),
        imageParams);
    }
    catch (Exception ex) {
      return null;
    }
  }

  /**
   * Obtain an instance of {@link VisibleSigImage}
   * @param imgRef identifier for the visible signature SVG image
   * @param page the page where the image is to be included (0 = last page)
   * @param xOffset the x axis location of the image
   * @param yOffset the y axis (height) location of the image
   * @param zoomPercent the zoom percentage. The lowest value is -100 = -100% = infinitely small
   * @param personalizationParams map of all parameters to be included in the sign image
   *                              The map key value must be reflected by the capability of the references SVG image.
   * @return {@link VisibleSigImage}
   * @throws IllegalArgumentException on illegal input
   */
  public VisibleSigImage getVisibleSignImage(String imgRef, int page, int xOffset, int yOffset, int zoomPercent,
    Map<String, String> personalizationParams) throws IllegalArgumentException {

    Optional<? extends PdfSignatureImageTemplate> imageTemplateOptional = pdfSignatureImageTemplates.stream()
      .filter(template -> template.getReference().equals(imgRef))
      .findFirst();

    if (!imageTemplateOptional.isPresent()) {
      throw new IllegalArgumentException("Illegal image reference");
    }

    PdfSignatureImageTemplate imageTemplate = (PdfSignatureImageTemplate) imageTemplateOptional.get();

    return new VisibleSigImage(
      page, xOffset, yOffset, zoomPercent, personalizationParams,
      imageTemplate.getWidth(),
      imageTemplate.getHeight(),
      imageTemplate.isIncludeSigningTime(),
      imageTemplate.getImage()
    );
  }
}
