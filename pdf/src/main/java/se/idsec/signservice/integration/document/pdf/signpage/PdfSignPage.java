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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.pdfbox.pdmodel.PDDocument;

import lombok.Getter;
import lombok.Setter;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureRequirement;

/**
 * This class provides the basic logic for adding sign pages to PDF documents.
 * <p>
 * The functions of this class is strictly speaking not a part of the sing service integration API. It is rather a
 * helper class that may be used by the requesting e-service to generate the {@link VisiblePdfSignatureRequirement}
 * requirements for a PDF document being signed.
 * </p>
 * <p>
 * The PdfSignPage holds:
 * </p>
 * <ul>
 * <li>Information both about an optional extra sign page added to signed PDF document.</li>
 * <li>Reference to the sign image.</li>
 * <li>Logic for determining the signer name requirements.</li>
 * <li>Logic for determining the sign image placement.</li>
 * <li>Base placement for sign images.</li>
 * </ul>
 * <p>
 * Based on this data, the PdfSignImage is a one stop shop both for adding a sign page and for adding sign images to a
 * PDF document being signed.
 * </p>
 *
 * @deprecated Use {@link DefaultPdfSignaturePagePreparator} instead
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Deprecated
public class PdfSignPage {

  public static final String SUBFILTER_ETSI_RFC3161 = "ETSI.RFC3161";
  private final String signPageTemplateLocation;
  private final boolean onlyAddedToUnsigned;
  private final SignerNameRequirementProcessor signerNameRequirementProcessor;
  @Setter
  private SignatureImagePlacement basePlacement;
  private final SignatureImagePlacementCalulator calulator;
  @Setter
  @Getter
  private String imageTemplate;

  /**
   * The default constructor returning a fully functional SignPage functionality. This constructor is used when the
   * implementation intends to add a sign page with relative sign image placement to signed PDF documents.
   *
   * @param signPageTemplateLocation
   *          the location of the sign page template holding a valid PDF document where page 1 holds the template page
   * @param onlyAddedToUnsigned
   *          only add the sign page to unsigned documents
   * @param signerNameRequirementProcessor
   *          processor that determines the attributes and format for expressing signer name
   * @param basePlacement
   *          the base placement for sign images on the template page
   * @param calulator
   *          the calculator determining the change in position for each sign image relative to the number of current
   *          signatures. A null value creates a default calculator that always returns the base placement
   * @param imageTemplate
   *          the sign image template name
   */
  public PdfSignPage(final String signPageTemplateLocation, final boolean onlyAddedToUnsigned,
      final SignerNameRequirementProcessor signerNameRequirementProcessor,
      final SignatureImagePlacement basePlacement,
      final SignatureImagePlacementCalulator calulator, final String imageTemplate) {
    this.signPageTemplateLocation = signPageTemplateLocation;
    this.onlyAddedToUnsigned = onlyAddedToUnsigned;
    this.signerNameRequirementProcessor = signerNameRequirementProcessor;
    this.basePlacement = basePlacement;
    this.calulator = calulator == null ? (sigCount, basePlacement1) -> basePlacement1
        : calulator;
    this.imageTemplate = imageTemplate;
  }

  /**
   * Constructs a sign page instance that never adds any sign page but places a sign image on the original PDF document
   * at a defined location
   *
   * @param signerNameRequirementProcessor
   *          processor that determines the attributes and format for expressing signer name
   * @param basePlacement
   *          the base placement for sign images on the template page
   * @param calulator
   *          the calculator determining the change in position for each sign image relative to the number of current
   *          signatures. A null value creates a default calculator that always returns the base placement
   * @param imageTemplate
   *          the sign image template name
   */
  public PdfSignPage(final SignerNameRequirementProcessor signerNameRequirementProcessor, final SignatureImagePlacement basePlacement,
      final SignatureImagePlacementCalulator calulator, final String imageTemplate) {
    this.signPageTemplateLocation = null;
    this.onlyAddedToUnsigned = false;
    this.signerNameRequirementProcessor = signerNameRequirementProcessor;
    this.basePlacement = basePlacement;
    this.calulator = calulator == null
        ? (sigCount, basePlacement1) -> basePlacement1
        : calulator;
    this.imageTemplate = imageTemplate;
  }

  /**
   * Creates a NULL sign page that never adds a sign page and never adds a sign image
   */
  public PdfSignPage() {
    this.signPageTemplateLocation = null;
    this.signerNameRequirementProcessor = null;
    this.onlyAddedToUnsigned = false;
    this.basePlacement = null;
    this.calulator = (sigCount, basePlacement) -> basePlacement;
    this.imageTemplate = null;
  }

  /**
   * Creates a NULL sign page that never adds a sign page and always returns the base placement and default image
   * template
   *
   * <p>
   * This constructor is intended for the situation where the PDF document to be signed:
   * </p>
   * <ul>
   * <li>already have a suitable location for adding the sign image without adding a sign page</li>
   * <li>never will be signed more than once</li>
   * </ul>
   *
   * @param placement
   *          base placement for sign images
   * @param imageTemplate
   *          the identifier for the sign image
   */
  public PdfSignPage(final SignatureImagePlacement placement, final String imageTemplate) {
    this.signPageTemplateLocation = null;
    this.signerNameRequirementProcessor = null;
    this.onlyAddedToUnsigned = false;
    this.basePlacement = placement;
    this.calulator = (sigCount, basePlacement) -> basePlacement;
    this.imageTemplate = imageTemplate;
  }

  /**
   * Gets the PDF sign page document holding the sign page as page 0
   * <p>
   * The page returned from this method is not closed. It is therefore important to close this document after its use.
   * </p>
   *
   * @return document with sign page
   * @throws IOException
   *           on error
   */
  private PDDocument getSignPageDocument() throws IOException {
    if (this.signPageTemplateLocation == null) {
      return null;
    }
    InputStream is;
    if (this.signPageTemplateLocation.startsWith("classpath:")) {
      is = this.getClass().getResourceAsStream("/" + this.signPageTemplateLocation.substring(10));
    }
    else {
      final String fileSource = this.signPageTemplateLocation.startsWith("file://") ? this.signPageTemplateLocation.substring(7)
          : this.signPageTemplateLocation;
      is = new FileInputStream(new File(fileSource));
    }
    return PDDocument.load(is);
  }

  /**
   * Return the document to sign with signature page. Only add signature page to unsigned PDF if onlyAddedToUnsigned is
   * set to true
   *
   * @param tbsDocBytes
   *          bytes of the document to be signed
   * @return document to be signed with signature page added.
   * @throws IOException
   *           on invalid input
   */
  public byte[] getTbsDocumentWithSigPage(final byte[] tbsDocBytes) throws IOException {
    if (this.signPageTemplateLocation == null) {
      // This is a null sign page. Add no sign page.
      return tbsDocBytes;
    }

    if (!this.onlyAddedToUnsigned) {
      return this.appendDoc(tbsDocBytes);
    }
    PDDocument tbsDoc = null;
    try {
      tbsDoc = PDDocument.load(tbsDocBytes);
      final int sigCount = tbsDoc.getSignatureDictionaries().size();
      if (sigCount == 0) {
        return this.appendDoc(tbsDocBytes);
      }
      return tbsDocBytes;
    }
    finally {
      if (tbsDoc != null) {
        tbsDoc.close();
      }
    }
  }

  /**
   * Appends the sign page to the document to be signed
   *
   * @param tbsDocbytes
   *          the bytes of the document to be signed
   * @return a new document to be signed with an appended sign page
   * @throws IOException
   *           on invalid input
   */
  private byte[] appendDoc(final byte[] tbsDocbytes) throws IOException {
    PDDocument tbsDoc = null;
    PDDocument signPage = null;
    try {
      tbsDoc = PDDocument.load(tbsDocbytes);
      signPage = this.getSignPageDocument();
      tbsDoc.addPage(signPage.getPage(0));
      final ByteArrayOutputStream bos = new ByteArrayOutputStream();
      tbsDoc.save(bos);
      return bos.toByteArray();
    }
    finally {
      if (tbsDoc != null) {
        tbsDoc.close();
      }
      if (signPage != null) {
        signPage.close();
      }
    }
  }

  /**
   * Get the sign image placement for the next signature on this document
   *
   * @param tbsDocBytes
   *          the bytes of the document to be signed
   * @return sign image placement
   * @throws IOException
   *           on invalid input
   */
  public SignatureImagePlacement getSignImagePlacement(final byte[] tbsDocBytes) throws IOException {
    PDDocument pdDocument = null;
    try {
      pdDocument = PDDocument.load(tbsDocBytes);
      final int sigCount = pdDocument.getSignatureDictionaries().stream()
        .filter(signature -> !signature.getSubFilter().equalsIgnoreCase(SUBFILTER_ETSI_RFC3161))
        .collect(Collectors.toList()).size();
      return this.calulator.getPlacement(sigCount, this.basePlacement);
    }
    finally {
      if (pdDocument != null) {
        pdDocument.close();
      }
    }
  }

  public SignatureImagePlacement getSignImagePlacement(final PDDocument tbsDoc) throws IOException {
    final int sigCount = tbsDoc.getSignatureDictionaries().stream()
      .filter(signature -> !signature.getSubFilter().equalsIgnoreCase(SUBFILTER_ETSI_RFC3161))
      .collect(Collectors.toList()).size();
    return this.calulator.getPlacement(sigCount, this.basePlacement);
  }

  /**
   * Creates the visible signature requirements to forward to the sign service integration API.
   *
   * @param docBytes
   *          bytes of the document to be signed
   * @param docType
   *          the type of document to sign
   * @param signerAttrlist
   *          list of attributes of the signer passed to the signature service
   * @param imageParams
   *          map of image parameters passed to the sign image in addition to name and time of signing
   * @return the visible signature requirements
   * @throws IOException
   *           on error
   */
  public VisiblePdfSignatureRequirement getVisibleSignatureRequirement(
      final byte[] docBytes,
      final DocumentType docType,
      final List<SignerIdentityAttributeValue> signerAttrlist,
      Map<String, String> imageParams) throws IOException {

    if (!docType.equals(DocumentType.PDF)) {
      // This only applies to PDF documents
      return null;
    }

    if (this.imageTemplate == null) {
      // No sign image template specified
      return getNoVisibleSignatureRequirement();
    }

    // Get pdf document and check if the image should be displayed
    final SignatureImagePlacement signImagePlacement = this.getSignImagePlacement(docBytes);
    if (signImagePlacement == null || signImagePlacement.isHide() == true) {
      // Sign image placement is null or there is a sign page configuration that prevents the sign image from being
      // added to this page. Abort
      return getNoVisibleSignatureRequirement();
    }

    VisiblePdfSignatureRequirement.SignerName signerName = null;
    if (this.signerNameRequirementProcessor != null) {
      final SignerNameRequirement signerNameRequirements = this.signerNameRequirementProcessor.getSignerNameRequirements(signerAttrlist);
      final List<SignerIdentityAttribute> attributeList = signerNameRequirements.getSignerNameAttributeList();
      final String formatString = signerNameRequirements.getFormatString();

      // Set signer name requirements if attribute list is not empty and we have a format string
      if (attributeList.size() > 0 && formatString != null) {
        signerName = VisiblePdfSignatureRequirement.SignerName.builder()
          .signerAttributes(attributeList)
          .formatting(formatString)
          .build();
      }
    }

    imageParams = imageParams == null ? new HashMap<>() : imageParams;

    return VisiblePdfSignatureRequirement.builder()
      .signerName(signerName)
      .templateImageRef(this.getImageTemplate())
      .fieldValues(imageParams)
      .page(signImagePlacement.getSignImagePage())
      .scale(signImagePlacement.getSignImageScale())
      .xPosition(signImagePlacement.getSignImageXpos())
      .yPosition(signImagePlacement.getSignImageYpos())
      .build();
  }

  private VisiblePdfSignatureRequirement getNoVisibleSignatureRequirement() {
    VisiblePdfSignatureRequirement visiblePdfSignatureRequirement = VisiblePdfSignatureRequirement.builder().build();
    visiblePdfSignatureRequirement.addExtensionValue(VisiblePdfSignatureRequirement.NULL_INDICATOR_EXTENSION, "true");
    return visiblePdfSignatureRequirement;
  }

}
