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
package se.idsec.signservice.integration.document.pdf.signpage.impl;

import lombok.AllArgsConstructor;
import lombok.Data;
import se.idsec.signservice.integration.document.pdf.signpage.SignImagePlacement;
import se.idsec.signservice.integration.document.pdf.signpage.SignImagePlacementCalulator;

@Data
@AllArgsConstructor
public class GenericSignImagePlacementCalculator implements SignImagePlacementCalulator {

  private int cols;
  private int rows;
  private int start;
  private int startXoffset;
  private int startYoffset;
  private int xIncrement;
  private int yIncrement;

  public GenericSignImagePlacementCalculator(int cols, int rows, int xIncrement, int yIncrement) {
    this.cols = cols;
    this.rows = rows;
    this.xIncrement = xIncrement;
    this.yIncrement = yIncrement;
    this.start = 0;
    this.startXoffset = 0;
    this.startYoffset = 0;
  }

  @Override public SignImagePlacement getPlacement(int sigCount, SignImagePlacement basePlacement) {
    if (sigCount < start) {
      return basePlacement;
    }
    int col = (sigCount - start) % cols;
    int row = (sigCount - start) / cols;

    if (row >= rows) {
      return new SignImagePlacement();
    }
    return new SignImagePlacement(startXoffset + col * xIncrement, startYoffset + row * yIncrement, basePlacement);
  }
}
