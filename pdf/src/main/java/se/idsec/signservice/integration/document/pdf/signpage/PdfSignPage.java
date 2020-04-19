package se.idsec.signservice.integration.document.pdf.signpage;

import lombok.Getter;
import lombok.Setter;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.pdf.VisiblePdfSignatureRequirement;

import java.io.*;
import java.util.*;

/**
 * This class provides the basic logic for adding signpages
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
   * Constructe a sign page instance that never adds any sign page but places a sign image on the original PDF document at a defined location
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
   *   <ul>
   *     <li>-already have a suitable location for adding the sign image without adding a sign page</li>
   *     <li>-never will be signed more than once</li>
   *   </ul>
   * </p>
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

  private PDPage getPage() throws IOException {
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
    return sigPageDoc.getPage(0);
  }

  /**
   * Return the document to sign with signature page. Only add signature page to unsigned PDF if onlyAddedToUnsigned is set to true
   *
   * @param tbsDoc Document to be signed
   * @return Document to be signed with signature page added.
   * @throws IOException
   */
  public PDDocument getTbsDocumentWithSigPage(PDDocument tbsDoc) throws IOException {
    if (signPageTemplateLocation == null) {
      // This is a null sign page. Add no sign page.
      return tbsDoc;
    }

    if (!onlyAddedToUnsigned) {
      return appendDoc(tbsDoc);
    }
    int sigCount = tbsDoc.getSignatureDictionaries().size();
    if (sigCount == 0) {
      return appendDoc(tbsDoc);
    }
    return tbsDoc;
  }

  private PDDocument appendDoc(PDDocument tbsDoc) throws IOException {
    tbsDoc.addPage(getPage());
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    tbsDoc.save(bos);
    tbsDoc.close();
    PDDocument extendedPdf = PDDocument.load(bos.toByteArray());
    bos.close();
    return extendedPdf;
  }

  /**
   * Return the document to sign with signature page. Only add signature page to unsigned PDF if onlyAddedToUnsigned is set to true
   *
   * @param tbsDocBytes bytes of the document to be signed
   * @return document to be signed with signature page added.
   * @throws IOException
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
    int sigCount = tbsDoc.getSignatureDictionaries().size();
    if (sigCount == 0) {
      return appendDoc(tbsDocBytes);
    }
    return tbsDocBytes;
  }

  private byte[] appendDoc(byte[] tbsDocbytes) throws IOException {
    PDDocument tbsDoc = PDDocument.load(tbsDocbytes);
    tbsDoc.addPage(getPage());
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    tbsDoc.save(bos);
    tbsDoc.close();
    bos.close();
    return bos.toByteArray();
  }

  public SignImagePlacement getSignImagePlacement(byte[] tbsDocBytes) throws IOException {
    int sigCount = PDDocument.load(tbsDocBytes).getSignatureDictionaries().size();
    return calulator.getPlacement(sigCount, basePlacement);
  }

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
  public SignImagePlacement getSignImagePlacement(PDDocument tbsDoc) throws IOException {
    int sigCount = tbsDoc.getSignatureDictionaries().size();
    return calulator.getPlacement(sigCount, basePlacement);
  }

  /**
   * Creates the visible signature requirements to forward to the sign service integration API.
   *
   * @param docBytes
   * @param docType
   * @param signerAttrlist
   * @param imageParams    the entity id of the idp
   * @return
   * @throws IOException
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
