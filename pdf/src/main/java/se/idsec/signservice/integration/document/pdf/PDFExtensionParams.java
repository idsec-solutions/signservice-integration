/*
 * Copyright 2019-2023 IDsec Solutions AB
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
package se.idsec.signservice.integration.document.pdf;

import se.idsec.signservice.integration.document.pdf.visiblesig.VisibleSignatureImageSerializer;
import se.idsec.signservice.security.sign.pdf.document.VisibleSignatureImage;

/**
 * Extension parameters for {@link se.idsec.signservice.integration.document.TbsDocument} extensions.
 */
public enum PDFExtensionParams {

  /** Signing time an ID parameter, holding a long value representing the signing time used in the pre-sign process. */
  signTimeAndId,

  /** Base64Encoded bytes of CMS Content Info holding the SignedData from the pre-sign process. */
  cmsSignedData,

  /** Serialized {@link VisibleSignatureImage} using the {@link VisibleSignatureImageSerializer}. */
  visibleSignImage,

  /** ADeS requirement string. */
  adesRequirement
}
