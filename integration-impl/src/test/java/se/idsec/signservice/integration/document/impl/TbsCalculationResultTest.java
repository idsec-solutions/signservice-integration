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

import org.junit.Assert;
import org.junit.Test;

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

    Assert.assertEquals("XML", r.getSigType());
    Assert.assertArrayEquals("bytes".getBytes(), r.getToBeSignedBytes());
    Assert.assertEquals("ID", r.getAdesSignatureId());
    Assert.assertArrayEquals("ades".getBytes(), r.getAdesObjectBytes());
  }

  @Test
  public void testBuilder() throws Exception {
    TbsCalculationResult r = TbsCalculationResult.builder()
        .sigType("XML")
        .toBeSignedBytes("bytes".getBytes())
        .adesSignatureId("ID")
        .adesObjectBytes("ades".getBytes())
        .build();

    Assert.assertEquals("XML", r.getSigType());
    Assert.assertArrayEquals("bytes".getBytes(), r.getToBeSignedBytes());
    Assert.assertEquals("ID", r.getAdesSignatureId());
    Assert.assertArrayEquals("ades".getBytes(), r.getAdesObjectBytes());

    r = TbsCalculationResult.builder().build();

    Assert.assertNull(r.getSigType());
    Assert.assertNull(r.getToBeSignedBytes());
    Assert.assertNull(r.getAdesSignatureId());
    Assert.assertNull(r.getAdesObjectBytes());

    Assert.assertTrue(TbsCalculationResult.builder().toString().startsWith("TbsCalculationResult.TbsCalculationResultBuilder"));
  }


}
