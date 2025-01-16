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
package se.idsec.signservice.integration.document.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for {@code TbsCalculationResult}. Mainly to get code coverage.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class TbsCalculationResultTest {

  @Test
  public void testCreate() throws Exception {
    TbsCalculationResult r = new TbsCalculationResult();
    r.setSigType("XML");
    r.setToBeSignedBytes("bytes".getBytes());
    r.setAdesSignatureId("ID");
    r.setAdesObjectBytes("ades".getBytes());

    Assertions.assertEquals("XML", r.getSigType());
    Assertions.assertArrayEquals("bytes".getBytes(), r.getToBeSignedBytes());
    Assertions.assertEquals("ID", r.getAdesSignatureId());
    Assertions.assertArrayEquals("ades".getBytes(), r.getAdesObjectBytes());
  }

  @Test
  public void testBuilder() throws Exception {
    TbsCalculationResult r = TbsCalculationResult.builder()
        .sigType("XML")
        .toBeSignedBytes("bytes".getBytes())
        .adesSignatureId("ID")
        .adesObjectBytes("ades".getBytes())
        .build();

    Assertions.assertEquals("XML", r.getSigType());
    Assertions.assertArrayEquals("bytes".getBytes(), r.getToBeSignedBytes());
    Assertions.assertEquals("ID", r.getAdesSignatureId());
    Assertions.assertArrayEquals("ades".getBytes(), r.getAdesObjectBytes());

    r = TbsCalculationResult.builder().build();

    Assertions.assertNull(r.getSigType());
    Assertions.assertNull(r.getToBeSignedBytes());
    Assertions.assertNull(r.getAdesSignatureId());
    Assertions.assertNull(r.getAdesObjectBytes());

    Assertions.assertTrue(TbsCalculationResult.builder().toString().startsWith("TbsCalculationResult.TbsCalculationResultBuilder"));
  }


}
