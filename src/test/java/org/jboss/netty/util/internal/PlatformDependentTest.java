/*
 * Copyright 2021 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.jboss.netty.util.internal;

import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;
import static org.junit.Assume.*;

/**
 * Unit test for {@link PlatformDependent}.
 */
public class PlatformDependentTest {

    @Test
    public void testCreateTempFileWithNullDirectory() throws IOException {
        File file = PlatformDependent.createTempFile("netty-test-", ".tmp", null);
        try {
            assertTrue(file.isFile());
            assertTrue(file.getName().startsWith("netty-test-"));
            assertTrue(file.getName().endsWith(".tmp"));
            assertEquals(0, file.length());
            assertEquals(new File(System.getProperty("java.io.tmpdir")).getCanonicalFile(),
                    file.getParentFile().getCanonicalFile());
            assertTrue(file.canRead());
            assertTrue(file.canWrite());
        } finally {
            assertTrue(file.delete());
        }
    }

    @Test
    public void testCreateTempFileWithDirectory() throws IOException {
        File dir = newTempDirectory();
        try {
            File file = PlatformDependent.createTempFile("netty-test-", ".tmp", dir);
            try {
                assertTrue(file.isFile());
                assertTrue(file.getName().startsWith("netty-test-"));
                assertTrue(file.getName().endsWith(".tmp"));
                assertEquals(dir.getCanonicalFile(), file.getParentFile().getCanonicalFile());
                assertTrue(file.canRead());
                assertTrue(file.canWrite());
            } finally {
                assertTrue(file.delete());
            }
        } finally {
            assertTrue(dir.delete());
        }
    }

    @Test
    public void testCreateTempFileCreatesUniqueFiles() throws IOException {
        File file1 = PlatformDependent.createTempFile("netty-test-", ".tmp", null);
        try {
            File file2 = PlatformDependent.createTempFile("netty-test-", ".tmp", null);
            try {
                assertFalse(file1.equals(file2));
            } finally {
                assertTrue(file2.delete());
            }
        } finally {
            assertTrue(file1.delete());
        }
    }

    /**
     * CVE-2021-21290: a temporary file must not be readable by other local users.
     */
    @Test
    public void testCreateTempFileIsOnlyReadableByOwner() throws Exception {
        File file = PlatformDependent.createTempFile("netty-perm-", ".tmp", null);
        try {
            assertOnlyReadableByOwner(file);
        } finally {
            assertTrue(file.delete());
        }
    }

    /**
     * CVE-2021-21290: a temporary file created in a given directory must not be
     * readable by other local users.
     */
    @Test
    public void testCreateTempFileInDirectoryIsOnlyReadableByOwner() throws Exception {
        File dir = newTempDirectory();
        try {
            File file = PlatformDependent.createTempFile("netty-perm-", ".tmp", dir);
            try {
                assertOnlyReadableByOwner(file);
            } finally {
                assertTrue(file.delete());
            }
        } finally {
            assertTrue(dir.delete());
        }
    }

    @Test
    public void testCreateTempFileWithNameSeparatorInSuffixThrowsIOException() throws IOException {
        File dir = newTempDirectory();
        try {
            try {
                PlatformDependent.createTempFile("netty-test-", "/../escaped.tmp", dir);
                fail("expected IOException");
            } catch (IOException expected) {
                // expected
            }
            String[] children = dir.list();
            assertNotNull(children);
            assertEquals(0, children.length);
        } finally {
            assertTrue(dir.delete());
        }
    }

    @Test(expected = IOException.class)
    public void testCreateTempFileInMissingDirectoryThrowsIOException() throws IOException {
        File dir = newTempDirectory();
        assertTrue(dir.delete());
        PlatformDependent.createTempFile("netty-test-", ".tmp", dir);
    }

    private static File newTempDirectory() throws IOException {
        File dir = File.createTempFile("netty-test-dir-", "");
        assertTrue(dir.delete());
        assertTrue(dir.mkdir());
        return dir;
    }

    private static void assertOnlyReadableByOwner(File file) throws Exception {
        assertTrue(file.canRead());
        Set<String> permissions = posixFilePermissions(file);
        assumeNotNull(permissions);
        assertTrue(permissions.toString(), permissions.contains("OWNER_READ"));
        assertFalse(permissions.toString(), permissions.contains("GROUP_READ"));
        assertFalse(permissions.toString(), permissions.contains("OTHERS_READ"));
    }

    /**
     * Returns the names of the POSIX permissions of the given file, or {@code null} if they
     * can not be determined (Java 6 and older or a file system without POSIX permissions).
     */
    private static Set<String> posixFilePermissions(File file) throws Exception {
        Class<?> filesClass;
        try {
            filesClass = Class.forName("java.nio.file.Files");
        } catch (ClassNotFoundException e) {
            return null;
        }
        Class<?> pathClass = Class.forName("java.nio.file.Path");
        Object emptyLinkOptions = Array.newInstance(Class.forName("java.nio.file.LinkOption"), 0);
        Method getPosixFilePermissions = filesClass.getMethod(
                "getPosixFilePermissions", pathClass, emptyLinkOptions.getClass());
        Object path = File.class.getMethod("toPath").invoke(file);
        Set<?> permissions;
        try {
            permissions = (Set<?>) getPosixFilePermissions.invoke(null, path, emptyLinkOptions);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof UnsupportedOperationException) {
                return null;
            }
            throw e;
        }
        Set<String> names = new HashSet<String>();
        for (Object permission: permissions) {
            names.add(String.valueOf(permission));
        }
        return names;
    }
}
