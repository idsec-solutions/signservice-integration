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
package se.idsec.signservice.integration.document;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import se.idsec.signservice.integration.document.ades.AdesObject;

/**
 * An interface that is used to represent a signed document that is the compilation of the TBS document from the
 * SignRequest and the signature from the SignResponse.
 * 
 * @param <T>
 *          the document type
 * @param <X>
 *          the AdES object from the signature
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CompiledSignedDocument<T, X extends AdesObject> {

  /**
   * Gets the signed document.
   * 
   * @return the signed document
   */
  @Nonnull
  T getDocument();

  /**
   * Gets the {@link SignedDocument} to be returned back in the result to the caller.
   * 
   * @return a SignedDocument object
   */
  @Nonnull
  SignedDocument getSignedDocument();

  /**
   * Gets the AdES object (if present in the signature)
   * 
   * @return the AdES object, or null
   */
  @Nullable
  X getAdesObject();

}
