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

import lombok.Data;

/**
 * Holding the sign image placement data for placing a sign image in a PDF document.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
public class SignatureImagePlacement {
  private int signImageXpos;
  private int singImaeYpos;
  private int signImageScale;
  private int signImagePage;
  private boolean hide = false;

  /**
   * Create NULL placement for not placing sign image at all.
   */
  public SignatureImagePlacement() {
    this.signImageXpos = 0;
    this.singImaeYpos = 0;
    this.signImagePage = 0;
    this.signImageScale = 0;
    this.hide = true;
  }

  /**
   * Create sign image placement.
   *
   * @param signImageXpos
   *          image X coordinate
   * @param singImaeYpos
   *          image Y coordinate
   * @param signImageScale
   *          zoom percentage
   * @param signImagePage
   *          1 based page placement. 0 for last page
   */
  public SignatureImagePlacement(final int signImageXpos, final int singImaeYpos, final int signImageScale, final int signImagePage) {
    this.signImageXpos = signImageXpos;
    this.singImaeYpos = singImaeYpos;
    this.signImageScale = signImageScale;
    this.signImagePage = signImagePage;
  }

  /**
   * Get new sign image placement with relative location change.
   *
   * @param addX
   *          add placement this number of pixels on the x axis
   * @param addY
   *          add placement this number of pixels on the y axis
   * @param basePlacement
   *          the base placement
   */
  public SignatureImagePlacement(final int addX, final int addY, final SignatureImagePlacement basePlacement) {
    this.signImageXpos = basePlacement.getSignImageXpos() + addX;
    this.singImaeYpos = basePlacement.getSingImaeYpos() + addY;
    this.signImagePage = basePlacement.getSignImagePage();
    this.signImageScale = basePlacement.getSignImageScale();
  }

  /**
   * Get new sign image placement with relative location change.
   *
   * @param addX
   *          add placement this number of pixels on the x axis
   * @param addY
   *          add placement this number of pixels on the y axis
   * @param signImageScale
   *          new scale
   * @param basePlacement
   *          the base placement
   */
  public SignatureImagePlacement(final int addX, final int addY, final int signImageScale, final SignatureImagePlacement basePlacement) {
    this.signImageXpos = basePlacement.getSignImageXpos() + addX;
    this.singImaeYpos = basePlacement.getSingImaeYpos() + addY;
    this.signImageScale = signImageScale;
    this.signImagePage = basePlacement.getSignImagePage();
  }
}
