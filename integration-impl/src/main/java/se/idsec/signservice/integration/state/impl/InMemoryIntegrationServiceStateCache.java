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
package se.idsec.signservice.integration.state.impl;

import se.idsec.signservice.integration.core.impl.AbstractInMemoryIntegrationServiceCache;
import se.idsec.signservice.integration.state.CacheableSignatureState;
import se.idsec.signservice.integration.state.IntegrationServiceStateCache;

/**
 * A simple in-memory implementation of the {@link IntegrationServiceStateCache} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class InMemoryIntegrationServiceStateCache extends AbstractInMemoryIntegrationServiceCache<CacheableSignatureState>
  implements IntegrationServiceStateCache {

}
