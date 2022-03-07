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
package se.idsec.signservice.integration.dss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.junit.Assert;
import org.junit.Test;

/**
 * Test cases for SignRequestWrapper.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SignRequestWrapperTest {

  @Test
  public void testJavaSerialization() throws Exception {

    final SignRequestWrapper w1 = new SignRequestWrapper();
    w1.setRequestID("ABC");
    w1.setProfile("foo");

    // Serialize
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream out = new ObjectOutputStream(bos);
    out.writeObject(w1);
    byte[] serialization = bos.toByteArray();
    Assert.assertNotNull(serialization);

    // Deserialize
    ByteArrayInputStream bis = new ByteArrayInputStream(serialization);
    ObjectInputStream in = new ObjectInputStream(bis);
    final SignRequestWrapper w2 = (SignRequestWrapper) in.readObject();
    Assert.assertNotNull(w2);
    Assert.assertEquals(w1.getRequestID(), w2.getRequestID());
    Assert.assertEquals(w1.getProfile(), w2.getProfile());
  }

}
