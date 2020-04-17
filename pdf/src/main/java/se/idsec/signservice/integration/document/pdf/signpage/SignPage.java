package se.idsec.signservice.integration.document.pdf.signpage;

import lombok.Getter;
import lombok.Setter;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;

import java.io.*;

public class SignPage {

  private final String templateLocation;
  private final boolean onlyAddedToUnsigned;
  @Setter
  private SignImagePlacement basePlacement;
  private final SignImagePlacementCalulator calulator;
  @Setter
  @Getter
  private String imageTemplate;

  public SignPage(String templateLocation, boolean onlyAddedToUnsigned,
    SignImagePlacement basePlacement,
    SignImagePlacementCalulator calulator, String imageTemplate) {
    this.templateLocation = templateLocation;
    this.onlyAddedToUnsigned = onlyAddedToUnsigned;
    this.basePlacement = basePlacement;
    this.calulator = calulator;
    this.imageTemplate = imageTemplate;
  }

  /**
   * Creates a NULL sign page that never adds a sign page and always returns the base placement
   */
  public SignPage(SignImagePlacement placement) {
    this.templateLocation = null;
    this.onlyAddedToUnsigned = false;
    this.basePlacement = placement;
    this.calulator = new SignImagePlacementCalulator() {
      @Override public SignImagePlacement getPlacement(int sigCount, SignImagePlacement basePlacement) {
        return basePlacement;
      }
    };
    this.imageTemplate = null;
  }

  /**
   * Creates a NULL sign page that never adds a sign page and always returns the base placement and default image template
   */
  public SignPage(SignImagePlacement placement, String imageTemplate) {
    this.templateLocation = null;
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
    InputStream is;
    if (templateLocation.startsWith("classpath:")){
      is = getClass().getResourceAsStream("/" + templateLocation.substring(10));
    } else {
      is = new FileInputStream(new File(templateLocation));
    }
    PDDocument sigPageDoc = PDDocument.load(is);
    return sigPageDoc.getPage(0);
  }

  /**
   * Return the document to sign with signature page. Only add signature page to unsigned PDF if onlyAddedToUnsigned is set to true
   * @param tbsDoc Document to be signed
   * @return Document to be signed with signature page added.
   * @throws IOException
   */
  public PDDocument getTbsDocumentWithSigPage(PDDocument tbsDoc) throws IOException {
    if (templateLocation == null) {
      // This is a null sign page. Add no sign page.
      return tbsDoc;
    }

    if (!onlyAddedToUnsigned){
      return appendDoc(tbsDoc);
    }
    int sigCount = tbsDoc.getSignatureDictionaries().size();
    if (sigCount ==0){
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
   * @param tbsDocBytes bytes of the document to be signed
   * @return document to be signed with signature page added.
   * @throws IOException
   */
  public byte[] getTbsDocumentWithSigPage(byte[] tbsDocBytes) throws IOException {
    if (templateLocation == null) {
      // This is a null sign page. Add no sign page.
      return tbsDocBytes;
    }

    if (!onlyAddedToUnsigned){
      return appendDoc(tbsDocBytes);
    }
    PDDocument tbsDoc = PDDocument.load(tbsDocBytes);
    int sigCount = tbsDoc.getSignatureDictionaries().size();
    if (sigCount ==0){
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

  public SignImagePlacement getSignImagePlacement(PDDocument tbsDoc) throws IOException {
    int sigCount = tbsDoc.getSignatureDictionaries().size();
    return calulator.getPlacement(sigCount, basePlacement);
  }



}
