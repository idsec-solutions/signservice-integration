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

/**
 * Provides the logic for determining the relative place of a sign image.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignatureImagePlacementCalulator {

  /**
   * Calculates the relative placement of a sign image based on the number of previously existing signatures on this
   * document.
   * 
   * @param sigCount
   *          number of already existing signatures on this document
   * @param basePlacement
   *          the base placement of sign images
   * @return placement for the next sign image
   */
  SignatureImagePlacement getPlacement(final int sigCount, final SignatureImagePlacement basePlacement);
}
