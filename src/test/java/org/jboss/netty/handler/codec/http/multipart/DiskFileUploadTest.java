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
package org.jboss.netty.handler.codec.http.multipart;

import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.ErrorDataDecoderException;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

import static org.jboss.netty.util.CharsetUtil.*;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

/**
 * CVE-2021-21290: the temporary files that hold the content of disk based
 * {@link HttpData} must not be readable by other local users.
 */
public class DiskFileUploadTest {

    private static final String BOUNDARY = "dLV9Wyq26L_-JQxk6ferf-RT153LhOO";

    @Test
    public void testDiskFileUploadSetContentIsOnlyReadableByOwner() throws Exception {
        DiskFileUpload upload = new DiskFileUpload("file", "secret.txt", "text/plain", null, UTF_8, 0);
        try {
            upload.setContent(ChannelBuffers.copiedBuffer("secret content", UTF_8));
            assertEquals("secret content", upload.getString(UTF_8));
            File file = upload.getFile();
            assertTrue(file.getName().startsWith(DiskFileUpload.prefix));
            assertTrue(file.getName().endsWith("_secret.txt"));
            assertOnlyReadableByOwner(file);
        } finally {
            upload.delete();
        }
    }

    @Test
    public void testDiskFileUploadAddContentIsOnlyReadableByOwner() throws Exception {
        DiskFileUpload upload = new DiskFileUpload("file", "secret.txt", "text/plain", null, UTF_8, 0);
        try {
            upload.addContent(ChannelBuffers.copiedBuffer("secret ", UTF_8), false);
            upload.addContent(ChannelBuffers.copiedBuffer("content", UTF_8), true);
            assertEquals("secret content", upload.getString(UTF_8));
            assertOnlyReadableByOwner(upload.getFile());
        } finally {
            upload.delete();
        }
    }

    @Test
    public void testDiskFileUploadSetContentFromStreamIsOnlyReadableByOwner() throws Exception {
        DiskFileUpload upload = new DiskFileUpload("file", "secret.txt", "text/plain", null, UTF_8, 0);
        try {
            upload.setContent(new ByteArrayInputStream("secret content".getBytes("UTF-8")));
            assertEquals("secret content", upload.getString(UTF_8));
            assertOnlyReadableByOwner(upload.getFile());
        } finally {
            upload.getFile().delete();
        }
    }

    @Test
    public void testDiskFileUploadInBaseDirectoryIsOnlyReadableByOwner() throws Exception {
        File dir = newTempDirectory();
        String oldBaseDirectory = DiskFileUpload.baseDirectory;
        DiskFileUpload.baseDirectory = dir.getAbsolutePath();
        try {
            DiskFileUpload upload = new DiskFileUpload("file", "secret.txt", "text/plain", null, UTF_8, 0);
            try {
                upload.setContent(ChannelBuffers.copiedBuffer("secret content", UTF_8));
                File file = upload.getFile();
                assertEquals(dir.getCanonicalFile(), file.getParentFile().getCanonicalFile());
                assertOnlyReadableByOwner(file);
            } finally {
                upload.delete();
            }
        } finally {
            DiskFileUpload.baseDirectory = oldBaseDirectory;
            assertTrue(dir.delete());
        }
    }

    @Test
    public void testDiskAttributeIsOnlyReadableByOwner() throws Exception {
        DiskAttribute attribute = new DiskAttribute("password", "secret value");
        try {
            assertEquals("secret value", attribute.getValue());
            File file = attribute.getFile();
            assertTrue(file.getName().startsWith(DiskAttribute.prefix));
            assertOnlyReadableByOwner(file);
        } finally {
            attribute.delete();
        }
    }

    @Test
    public void testDiskAttributeInBaseDirectoryIsOnlyReadableByOwner() throws Exception {
        File dir = newTempDirectory();
        String oldBaseDirectory = DiskAttribute.baseDirectory;
        DiskAttribute.baseDirectory = dir.getAbsolutePath();
        try {
            DiskAttribute attribute = new DiskAttribute("password");
            try {
                attribute.addContent(ChannelBuffers.copiedBuffer("secret value", UTF_8), true);
                File file = attribute.getFile();
                assertEquals(dir.getCanonicalFile(), file.getParentFile().getCanonicalFile());
                assertOnlyReadableByOwner(file);
            } finally {
                attribute.delete();
            }
        } finally {
            DiskAttribute.baseDirectory = oldBaseDirectory;
            assertTrue(dir.delete());
        }
    }

    @Test
    public void testMultipartUploadDecodedToDiskIsOnlyReadableByOwner() throws Exception {
        final String body =
                "--" + BOUNDARY + "\r\n" +
                "Content-Disposition: form-data; name=\"field\"\r\n" +
                "\r\n" +
                "secret value\r\n" +
                "--" + BOUNDARY + "\r\n" +
                "Content-Disposition: form-data; name=\"file\"; filename=\"secret.txt\"\r\n" +
                "Content-Type: text/plain\r\n" +
                "\r\n" +
                "secret content\r\n" +
                "--" + BOUNDARY + "--\r\n";

        // Force to use disk-based data.
        final DefaultHttpDataFactory factory = new DefaultHttpDataFactory(true);
        final HttpPostRequestDecoder decoder = new HttpPostRequestDecoder(factory, newMultipartRequest(body));
        try {
            InterfaceHttpData field = decoder.getBodyHttpData("field");
            assertTrue(String.valueOf(field), field instanceof DiskAttribute);
            DiskAttribute attribute = (DiskAttribute) field;
            assertEquals("secret value", attribute.getValue());
            assertOnlyReadableByOwner(attribute.getFile());

            InterfaceHttpData file = decoder.getBodyHttpData("file");
            assertTrue(String.valueOf(file), file instanceof DiskFileUpload);
            DiskFileUpload upload = (DiskFileUpload) file;
            assertEquals("secret content", upload.getString(UTF_8));
            assertOnlyReadableByOwner(upload.getFile());
        } finally {
            decoder.cleanFiles();
        }
    }

    @Test
    public void testDiskAttributeWithNameSeparatorInNameThrowsIOException() throws Exception {
        File dir = newTempDirectory();
        String oldBaseDirectory = DiskAttribute.baseDirectory;
        DiskAttribute.baseDirectory = dir.getAbsolutePath();
        try {
            DiskAttribute attribute = new DiskAttribute("a/../b");
            try {
                attribute.addContent(ChannelBuffers.copiedBuffer("value", UTF_8), true);
                fail("expected IOException");
            } catch (IOException expected) {
                // expected
            }
            String[] children = dir.list();
            assertNotNull(children);
            assertEquals(0, children.length);
        } finally {
            DiskAttribute.baseDirectory = oldBaseDirectory;
            assertTrue(dir.delete());
        }
    }

    @Test
    public void testMultipartFieldWithNameSeparatorInNameIsRejected() throws Exception {
        final String body =
                "--" + BOUNDARY + "\r\n" +
                "Content-Disposition: form-data; name=\"a/../b\"\r\n" +
                "\r\n" +
                "value\r\n" +
                "--" + BOUNDARY + "--\r\n";

        // Force to use disk-based data.
        final DefaultHttpDataFactory factory = new DefaultHttpDataFactory(true);
        try {
            new HttpPostRequestDecoder(factory, newMultipartRequest(body));
            fail("expected ErrorDataDecoderException");
        } catch (ErrorDataDecoderException expected) {
            // expected
        } finally {
            factory.cleanAllHttpDatas();
        }
    }

    private static DefaultHttpRequest newMultipartRequest(String body) {
        final DefaultHttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "http://localhost");
        req.setHeader(HttpHeaders.Names.CONTENT_TYPE, "multipart/form-data; boundary=" + BOUNDARY);
        req.setContent(ChannelBuffers.copiedBuffer(body, UTF_8));
        return req;
    }

    private static File newTempDirectory() throws IOException {
        File dir = File.createTempFile("netty-test-dir-", "");
        assertTrue(dir.delete());
        assertTrue(dir.mkdir());
        return dir;
    }

    private static void assertOnlyReadableByOwner(File file) throws Exception {
        assertNotNull(file);
        assertTrue(file.isFile());
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
