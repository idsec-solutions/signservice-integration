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
package se.idsec.signservice.integration.core;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

/**
 * Test cases for DefaultContentLoader. The API-project don't have Spring in the classpath, so we test this part here.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultContentLoaderTest {

  private static final byte[] expectedContents = "For testing DefaultContentLoader".getBytes(StandardCharsets.UTF_8);

  /*
  @Test
  public void testEnsureSpringLoaded() throws Exception {
    final DefaultContentLoader loader = new DefaultContentLoader();
    final Field field1 = loader.getClass().getDeclaredField("springContentLoader");
    field1.setAccessible(true);
    final Field field2 = loader.getClass().getDeclaredField("getResourceMethod");
    field2.setAccessible(true);

    Assertions.assertNotNull(field1.get(loader));
    Assertions.assertNotNull(field2.get(loader));
  }
   */

  @Test
  public void testLoadFromClasspath() throws Exception {
    final DefaultContentLoader loader = new DefaultContentLoader();
    byte[] contents = loader.loadContent("classpath:testfile.txt");
    Assertions.assertArrayEquals(expectedContents, contents);

    contents = loader.loadContent("classpath:/testfile.txt");
    Assertions.assertArrayEquals(expectedContents, contents);
  }

  @Test
  public void testLoadFromFile() throws Exception {
    final DefaultContentLoader loader = new DefaultContentLoader();
    final byte[] contents = loader.loadContent(String.format("file://%s/src/test/resources/testfile.txt",
        Paths.get("").toAbsolutePath()));
    Assertions.assertArrayEquals(expectedContents, contents);

    loader.loadContent(String.format("%s/src/test/resources/testfile.txt",
        Paths.get("").toAbsolutePath()));
    Assertions.assertArrayEquals(expectedContents, contents);
  }

  @Test
  public void testNoFile() {
    final DefaultContentLoader loader = new DefaultContentLoader();

    Assertions.assertThrows(IOException.class, () -> loader.loadContent("classpath:no-such-file.txt"));
    Assertions.assertThrows(IOException.class, () -> loader.loadContent("file://no-such-file.txt"));
    Assertions.assertThrows(IOException.class, () -> loader.loadContent("/home/user/no-such-file.txt"));
  }
}
