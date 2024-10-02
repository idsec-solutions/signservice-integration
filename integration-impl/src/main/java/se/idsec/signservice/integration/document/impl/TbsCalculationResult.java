/*
 * Copyright 2019-2022 IDsec Solutions AB
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
package se.idsec.signservice.integration.document.impl;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import se.idsec.signservice.integration.core.ObjectBuilder;

/**
 * Representation of the result object for
 * {@link AbstractTbsDocumentProcessor#calculateToBeSigned(se.idsec.signservice.integration.document.ProcessedTbsDocument, String, se.idsec.signservice.integration.config.IntegrationServiceConfiguration)}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TbsCalculationResult {

  /**
   * The {@code SignTaskData.SigType} attribute.
   */
  @Getter
  @Setter
  private String sigType;

  /**
   * The {@code SignTaskData.ToBeSignedBytes} element.
   */
  @Getter
  @Setter
  private byte[] toBeSignedBytes;

  /**
   * The {@code SignTaskData.AdESObject.SignatureId} element.
   */
  @Getter
  @Setter
  private String adesSignatureId;

  /**
   * The {@code SignTaskData.AdESObject.AdESObjectBytes} element.
   */
  @Getter
  @Setter
  private byte[] adesObjectBytes;

  /**
   * Builder for {@link TbsCalculationResult} objects.
   */
  public static class TbsCalculationResultBuilder implements ObjectBuilder<TbsCalculationResult> {
  }

}
