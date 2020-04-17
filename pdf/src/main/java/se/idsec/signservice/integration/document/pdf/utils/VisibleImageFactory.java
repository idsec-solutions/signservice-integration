package se.idsec.signservice.integration.document.pdf.utils;

import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureRequirement;
import se.idsec.signservice.pdf.sign.VisibleSigImage;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

public class VisibleImageFactory {

  private List<? extends PdfSignatureImageTemplate> pdfSignatureImageTemplates;

  public VisibleImageFactory(List<? extends PdfSignatureImageTemplate> pdfSignatureImageTemplates) {
    this.pdfSignatureImageTemplates = pdfSignatureImageTemplates;
  }

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
          Logger.getLogger(VisibleImageFactory.class.getName())
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
}
