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

import lombok.Getter;
import lombok.Setter;
import org.apache.pdfbox.pdmodel.PDDocument;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureRequirement;

import java.io.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class provides the basic logic for adding sign pages to PDF documents.
 * <p>
 *   The functions of this class is strictly speaking not a part of the sing service integration API.
 *   It is rather a helper class that may be used by the requesting e-service to generate the {@link VisiblePdfSignatureRequirement}
 *   requirements for a PDF document being signed.
 * </p>
 * <p>
 *   The PdfSignPage holds:
 * </p>
 *   <ul>
 *     <li>information both about an optional extra sign page added to signed PDF document</li>
 *     <li>Reference to the sign image</li>
 *     <li>Logic for determining the signer name requirements</li>
 *     <li>Logic for determining the sign image placement</li>
 *     <li>Base placement for sign images</li>
 *   </ul>
 *   <p>
 *     Based on this data, the PdfSignImage is a one stop shop both for adding a sign page and for adding sign images to a PDF document being
 *     signed
 *   </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PdfSignPage {

  private final String signPageTemplateLocation;
  private final boolean onlyAddedToUnsigned;
  private final SignerNameRequirementProcessor signerNameRequirementProcessor;
  @Setter
  private SignImagePlacement basePlacement;
  private final SignImagePlacementCalulator calulator;
  @Setter
  @Getter
  private String imageTemplate;

  /**
   * The default constructor returning a fully functional SignPage functionality. This constructor is used when the implementation
   * intends to add a sign page with relative sign image placement to signed PDF documents
   *
   * @param signPageTemplateLocation       the location of the sign page template holding a valid PDF document where page 1 holds the template page
   * @param onlyAddedToUnsigned            only add the sign page to unsigned documents
   * @param signerNameRequirementProcessor processor that determines the attributes and format for expressing signer name
   * @param basePlacement                  the base placement for sign images on the template page
   * @param calulator                      the calculator determining the change in position for each sign image relative to the number
   *                                       of current signatures. A null value creates a default calculator that always returns the base placement
   * @param imageTemplate                  the sign image template name
   */
  public PdfSignPage(String signPageTemplateLocation, boolean onlyAddedToUnsigned,
    SignerNameRequirementProcessor signerNameRequirementProcessor,
    SignImagePlacement basePlacement,
    SignImagePlacementCalulator calulator, String imageTemplate) {
    this.signPageTemplateLocation = signPageTemplateLocation;
    this.onlyAddedToUnsigned = onlyAddedToUnsigned;
    this.signerNameRequirementProcessor = signerNameRequirementProcessor;
    this.basePlacement = basePlacement;
    this.calulator = calulator == null ?
      new SignImagePlacementCalulator() {
        @Override public SignImagePlacement getPlacement(int sigCount, SignImagePlacement basePlacement) {
          return basePlacement;
        }
      }
      : calulator;
    this.imageTemplate = imageTemplate;
  }

  /**
   * Constructs a sign page instance that never adds any sign page but places a sign image on the original PDF document at a defined location
   *
   * @param signerNameRequirementProcessor processor that determines the attributes and format for expressing signer name
   * @param basePlacement                  the base placement for sign images on the template page
   * @param calulator                      the calculator determining the change in position for each sign image relative to the number
   *                                       of current signatures. A null value creates a default calculator that always returns the base placement
   * @param imageTemplate                  the sign image template name
   */
  public PdfSignPage(
    SignerNameRequirementProcessor signerNameRequirementProcessor,
    SignImagePlacement basePlacement,
    SignImagePlacementCalulator calulator, String imageTemplate) {    this.signPageTemplateLocation = null;
    this.onlyAddedToUnsigned = false;
    this.signerNameRequirementProcessor = signerNameRequirementProcessor;
    this.basePlacement = basePlacement;
    this.calulator = calulator == null ?
      new SignImagePlacementCalulator() {
        @Override public SignImagePlacement getPlacement(int sigCount, SignImagePlacement basePlacement) {
          return basePlacement;
        }
      }
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
    this.calulator = new SignImagePlacementCalulator() {
      @Override public SignImagePlacement getPlacement(int sigCount, SignImagePlacement basePlacement) {
        return basePlacement;
      }
    };
    this.imageTemplate = null;
  }

  /**
   * Creates a NULL sign page that never adds a sign page and always returns the base placement and default image template
   *
   * <p>
   * This constructor is intended for the situation where the PDF document to be signed:
   * </p>
   *   <ul>
   *     <li>-already have a suitable location for adding the sign image without adding a sign page</li>
   *     <li>-never will be signed more than once</li>
   *   </ul>
   *
   * @param placement base placement for sign images
   * @param imageTemplate the identifier for the sign image
   */
  public PdfSignPage(SignImagePlacement placement, String imageTemplate) {
    this.signPageTemplateLocation = null;
    this.signerNameRequirementProcessor = null;
    this.onlyAddedToUnsigned = false;
    this.basePlacement = placement;
    this.calulator = new SignImagePlacementCalulator() {
      @Override public SignImagePlacement getPlacement(int sigCount, SignImagePlacement basePlacement) {
        return basePlacement;
      }
    };
    this.imageTemplate = imageTemplate;
  }

  /**
   * Gets the PDF sign page document holding the sign page as page 0
   * <p>
   *   The page returned from this method is not closed. It is therefore important to close this document after its use.
   * </p>
   * @return document with sign page
   * @throws IOException on error
   */
  private PDDocument getSignPageDocument() throws IOException {
    if (signPageTemplateLocation == null) {
      return null;
    }
    InputStream is;
    if (signPageTemplateLocation.startsWith("classpath:")) {
      is = getClass().getResourceAsStream("/" + signPageTemplateLocation.substring(10));
    }
    else {
      String fileSource = signPageTemplateLocation.startsWith("file://") ? signPageTemplateLocation.substring(7) :
        signPageTemplateLocation;
      is = new FileInputStream(new File(fileSource));
    }
    PDDocument sigPageDoc = PDDocument.load(is);
    return sigPageDoc;
  }

  /**
   * Return the document to sign with signature page. Only add signature page to unsigned PDF if onlyAddedToUnsigned is set to true
   *
   * @param tbsDocBytes bytes of the document to be signed
   * @return document to be signed with signature page added.
   * @throws IOException on invalid input
   */
  public byte[] getTbsDocumentWithSigPage(byte[] tbsDocBytes) throws IOException {
    if (signPageTemplateLocation == null) {
      // This is a null sign page. Add no sign page.
      return tbsDocBytes;
    }

    if (!onlyAddedToUnsigned) {
      return appendDoc(tbsDocBytes);
    }
    PDDocument tbsDoc = PDDocument.load(tbsDocBytes);
    tbsDoc.close();
    int sigCount = tbsDoc.getSignatureDictionaries().size();
    if (sigCount == 0) {
      return appendDoc(tbsDocBytes);
    }
    return tbsDocBytes;
  }

  /**
   * Appends the sign page to the document to be signed
   * @param tbsDocbytes the bytes of the document to be signed
   * @return a new document to be signed with an appended sign page
   * @throws IOException on invalid input
   */
  private byte[] appendDoc(byte[] tbsDocbytes) throws IOException {
    PDDocument tbsDoc = PDDocument.load(tbsDocbytes);
    PDDocument signPage = getSignPageDocument();
    tbsDoc.addPage(signPage.getPage(0));
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    tbsDoc.save(bos);
    tbsDoc.close();
    bos.close();
    signPage.close();
    return bos.toByteArray();
  }

  /**
   * Get the sign image placement for the next signature on this document
   * @param tbsDocBytes the bytes of the document to be signed
   * @return sign image placement
   * @throws IOException on invalid input
   */
  public SignImagePlacement getSignImagePlacement(byte[] tbsDocBytes) throws IOException {
    PDDocument pdDocument = PDDocument.load(tbsDocBytes);
    int sigCount = pdDocument.getSignatureDictionaries().size();
    pdDocument.close();
    return calulator.getPlacement(sigCount, basePlacement);
  }

  public SignImagePlacement getSignImagePlacement(PDDocument tbsDoc) throws IOException {
    int sigCount = tbsDoc.getSignatureDictionaries().size();
    return calulator.getPlacement(sigCount, basePlacement);
  }

  /**
   * Creates the visible signature requirements to forward to the sign service integration API.
   *
   * @param docBytes bytes of the document to be signed
   * @param docType the type of document to sign
   * @param signerAttrlist list of attributes of the signer passed to the signature service
   * @param imageParams   map of image parameters passed to the sign image in addition to name and time of signing
   * @return the visible signature requirements
   * @throws IOException on error
   */
  public VisiblePdfSignatureRequirement getVisibleSignatureRequirement(
    byte[] docBytes,
    DocumentType docType,
    List<SignerIdentityAttributeValue> signerAttrlist,
    Map<String, String> imageParams) throws IOException {

    if (!docType.equals(DocumentType.PDF)) {
      // This only applies to PDF documents
      return null;
    }

    if (imageTemplate == null) {
      // No sign image template specified
      return null;
    }

    // Get pdf document and check if the image should be displayed
    SignImagePlacement signImagePlacement = getSignImagePlacement(docBytes);
    if (signImagePlacement == null || signImagePlacement.isHide() == true) {
      // Sign image placement is null or there is a sign page configuration that prevents the sign image from being added to this page. Abort
      return null;
    }

    VisiblePdfSignatureRequirement.SignerName signerName = null;
    if (signerNameRequirementProcessor != null) {
      SignerNameRequirement signerNameRequirements = signerNameRequirementProcessor.getSignerNameRequirements(signerAttrlist);
      List<SignerIdentityAttribute> attributeList = signerNameRequirements.getSignerNameAttributeList();
      String formatString = signerNameRequirements.getFormatString();

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
      .templateImageRef(getImageTemplate())
      .fieldValues(imageParams)
      .page(signImagePlacement.getSignImagePage())
      .scale(signImagePlacement.getSignImageScale())
      .xPosition(signImagePlacement.getSignImageXpos())
      .yPosition(signImagePlacement.getSingImaeYpos())
      .build();
  }

}
