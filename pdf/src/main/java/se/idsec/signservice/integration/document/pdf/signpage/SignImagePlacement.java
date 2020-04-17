package se.idsec.signservice.integration.document.pdf.signpage;

import lombok.Data;

@Data
public class SignImagePlacement {
  private int signImageXpos;
  private int singImaeYpos;
  private int signImageScale;
  private int signImagePage;
  private boolean hide = false;

  /**
   * Create NULL placement for not placing sign image at all.
   */
  public SignImagePlacement() {
    this.signImageXpos = 0;
    this.singImaeYpos = 0;
    this.signImagePage = 0;
    this.signImageScale = 0;
    this.hide = true;
  }

  /**
   * Create sign image placement
   * @param signImageXpos image X coordinate
   * @param singImaeYpos image Y coordinate
   * @param signImageScale zoom percentage
   * @param signImagePage 1 based page placement. 0 for last page
   */
  public SignImagePlacement(int signImageXpos, int singImaeYpos, int signImageScale, int signImagePage) {
    this.signImageXpos = signImageXpos;
    this.singImaeYpos = singImaeYpos;
    this.signImageScale = signImageScale;
    this.signImagePage = signImagePage;
  }

  /**
   * Get new sign image placement with relative location change
   * @param addX add placement this number of pixels on the x axis
   * @param addY add placement this number of pixels on the y axis
   * @param basePlacement the base placement
   */
  public SignImagePlacement(int addX, int addY, SignImagePlacement basePlacement) {
    this.signImageXpos = basePlacement.getSignImageXpos() + addX;
    this.singImaeYpos = basePlacement.getSingImaeYpos() + addY;
    this.signImagePage = basePlacement.getSignImagePage();
    this.signImageScale = basePlacement.getSignImageScale();
  }

  /**
   * Get new sign image placement with relative location change
   * @param addX add placement this number of pixels on the x axis
   * @param addY add placement this number of pixels on the y axis
   * @param signImageScale new scale
   * @param basePlacement the base placement
   */
  public SignImagePlacement(int addX, int addY, int signImageScale, SignImagePlacement basePlacement) {
    this.signImageXpos = basePlacement.getSignImageXpos() + addX;
    this.singImaeYpos = basePlacement.getSingImaeYpos() + addY;
    this.signImageScale = signImageScale;
    this.signImagePage = basePlacement.getSignImagePage();
  }
}
