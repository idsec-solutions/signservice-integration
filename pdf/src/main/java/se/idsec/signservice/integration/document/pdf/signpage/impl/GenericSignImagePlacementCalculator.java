/*
 * Copyright 2019-2025 IDsec Solutions AB
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
package se.idsec.signservice.integration.document.pdf.signpage.impl;

import lombok.AllArgsConstructor;
import lombok.Data;
import se.idsec.signservice.integration.document.pdf.signpage.SignatureImagePlacement;
import se.idsec.signservice.integration.document.pdf.signpage.SignatureImagePlacementCalulator;

/**
 * Implements a generic PDF sign image placement calculator.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
public class GenericSignImagePlacementCalculator implements SignatureImagePlacementCalulator {

  private int cols;
  private int rows;
  private int start;
  private int startXoffset;
  private int startYoffset;
  private int xIncrement;
  private int yIncrement;

  /**
   * Default constructor for the sign image calculator
   *
   * @param cols number of columns used to place sign images
   * @param rows number of maximum rows to place sign images
   * @param xIncrement the x-axis increment amount between sign images on the same row
   * @param yIncrement the y (height) axis increment amount between sign image rows
   */
  public GenericSignImagePlacementCalculator(final int cols, final int rows, final int xIncrement,
      final int yIncrement) {
    this.cols = cols;
    this.rows = rows;
    this.xIncrement = xIncrement;
    this.yIncrement = yIncrement;
    this.start = 0;
    this.startXoffset = 0;
    this.startYoffset = 0;
  }

  /** {@inheritDoc} */
  @Override
  public SignatureImagePlacement getPlacement(final int sigCount, final SignatureImagePlacement basePlacement) {
    if (sigCount < this.start) {
      return basePlacement;
    }
    final int col = (sigCount - this.start) % this.cols;
    final int row = (sigCount - this.start) / this.cols;

    if (row >= this.rows) {
      return new SignatureImagePlacement();
    }
    return new SignatureImagePlacement(this.startXoffset + col * this.xIncrement,
        this.startYoffset + row * this.yIncrement, basePlacement);
  }
}
