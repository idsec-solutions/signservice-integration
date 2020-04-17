package se.idsec.signservice.integration.document.pdf;

import se.idsec.signservice.integration.document.pdf.visiblesig.VisibleSigImageSerializer;

/**
 * Extension parameters for {@link se.idsec.signservice.integration.document.TbsDocument} extensions
 */
public enum PDFExtensionParams {
  /** Signing time an ID parameter, holding a long value representing the signing time used in the pre-sign process */
  signTimeAndId,
  /** Base64Encoded bytes of CMS Content Info holding the SignedData from the pre-sign process */
  cmsSignedData,
  /** Serialized {@link se.idsec.signservice.security.sign.pdf.document.VisibleSigImage} using the {@link VisibleSigImageSerializer} */
  visibleSignImage;
}
