/*
 * Copyright 2012 The Netty Project
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
package org.jboss.netty.handler.codec.http;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.embedder.CodecEmbedderException;
import org.jboss.netty.handler.codec.embedder.DecoderEmbedder;
import org.jboss.netty.util.CharsetUtil;

import org.junit.Test;

import static org.junit.Assert.*;

public class HttpMessageDecoderTest {

    @Test
    public void testHeaderWithNoValueAndMissingColon() {
        DecoderEmbedder<Object> embedder = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        String requestStr = "GET /some/path HTTP/1.1\r\n" +
                "Content-Length: 0\r\n" +
                "Host:\r\n" +
                "netty.io\r\n\r\n";

        try {
            embedder.offer(ChannelBuffers.copiedBuffer(requestStr, CharsetUtil.US_ASCII));
            fail("Expected CodecEmbedderException");
        } catch (CodecEmbedderException e) {
            assertTrue(e.getCause() instanceof IllegalArgumentException);
        }
    }

    @Test
    public void testMultipleContentLengthHeaders() {
        String requestStr = "GET /some/path HTTP/1.1\r\n" +
                "Content-Length: 1\r\n" +
                "Content-Length: 0\r\n\r\n" +
                "b";
        testInvalidHeaders0(requestStr);
    }

    @Test
    public void testMultipleContentLengthHeaders2() {
        String requestStr = "GET /some/path HTTP/1.1\r\n" +
                "Content-Length: 1\r\n" +
                "Connection: close\r\n" +
                "Content-Length: 0\r\n\r\n" +
                "b";
        testInvalidHeaders0(requestStr);
    }

    @Test
    public void testContentLengthHeaderWithCommaValue() {
        String requestStr = "GET /some/path HTTP/1.1\r\n" +
                "Content-Length: 1,1\r\n\r\n" +
                "b";
        testInvalidHeaders0(requestStr);
    }

    @Test
    public void testMultipleContentLengthHeadersWithFolding() {
        String requestStr = "POST / HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Connection: close\r\n" +
                "Content-Length: 5\r\n" +
                "Content-Length:\r\n" +
                "\t6\r\n\r\n" +
                "123456";
        testInvalidHeaders0(requestStr);
    }

    @Test
    public void testContentLengthAndTransferEncodingChunked() {
        String requestStr = "POST / HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Content-Length: 5\r\n" +
                "Transfer-Encoding: chunked\r\n\r\n" +
                "0\r\n\r\n";
        testInvalidHeaders0(requestStr);
    }

    // ---------------------------------------------------------------------
    // CVE-2026-42585: 'chunked' must be the final transfer coding, may only be
    // applied once, and a request carrying a Transfer-Encoding header without a
    // final 'chunked' coding must be rejected (RFC 9112 6.1 / 6.3).
    // ---------------------------------------------------------------------

    @Test
    public void testChunkedNotLastInTransferEncoding() {
        String requestStr = "GET /some/path HTTP/1.1\r\n" +
                "Transfer-Encoding: chunked, identity\r\n" +
                "Content-Length: 1\r\n" +
                "Host: netty.io\r\n\r\n" +
                "a";
        testInvalidHeaders0(requestStr);
    }

    @Test
    public void testInvalidTransferEncodingFramingChunkedIdentityWithContentLength() {
        testInvalidTransferEncodingFraming("Transfer-Encoding: chunked, identity\r\nContent-Length: 1\r\n");
    }

    @Test
    public void testInvalidTransferEncodingFramingChunkedThenGzipLine() {
        testInvalidTransferEncodingFraming("Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n");
    }

    @Test
    public void testInvalidTransferEncodingFramingChunkedGzipTrailingComma() {
        testInvalidTransferEncodingFraming("Transfer-Encoding: chunked, gzip,\r\n");
    }

    @Test
    public void testInvalidTransferEncodingFramingChunkedXchunked() {
        testInvalidTransferEncodingFraming("Transfer-Encoding: chunked, xchunked\r\n");
    }

    @Test
    public void testInvalidTransferEncodingFramingGzipOnly() {
        testInvalidTransferEncodingFraming("Transfer-Encoding: gzip\r\n");
    }

    @Test
    public void testInvalidTransferEncodingFramingChunkedSpaceGzipWithContentLength() {
        testInvalidTransferEncodingFraming("Transfer-Encoding: chunked gzip\r\nContent-Length: 1\r\n");
    }

    @Test
    public void testInvalidTransferEncodingFramingChunkedTwice() {
        testInvalidTransferEncodingFraming("Transfer-Encoding: chunked, chunked\r\n");
    }

    @Test
    public void testInvalidTransferEncodingFramingChunkedGzipChunked() {
        testInvalidTransferEncodingFraming("Transfer-Encoding: chunked, gzip, chunked\r\n");
    }

    @Test
    public void testInvalidTransferEncodingFramingChunkedTwiceMultiLine() {
        testInvalidTransferEncodingFraming("Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n");
    }

    @Test
    public void testInvalidTransferEncodingFramingChunkedTwiceMixedCaseWithEmptyElements() {
        testInvalidTransferEncodingFraming("Transfer-Encoding: Chunked, , CHUNKED,\r\n");
    }

    @Test
    public void testInvalidTransferEncodingFramingChunkedWithParameter() {
        testInvalidTransferEncodingFraming("Transfer-Encoding: chunked;foo=bar\r\n");
    }

    private static void testInvalidTransferEncodingFraming(String headers) {
        testInvalidHeaders0("GET /some/path HTTP/1.1\r\n" + headers + "Host: netty.io\r\n\r\n");
    }

    @Test
    public void testChunkedLastInMultiLineTransferEncodingGzipThenChunked() {
        testChunkedLastInMultiLineTransferEncoding("Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n");
    }

    @Test
    public void testChunkedLastInMultiLineTransferEncodingGzipThenChunkedTrailingComma() {
        testChunkedLastInMultiLineTransferEncoding("Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked,\r\n");
    }

    @Test
    public void testChunkedLastInMultiLineTransferEncodingChunkedThenEmptyElements() {
        testChunkedLastInMultiLineTransferEncoding("Transfer-Encoding: chunked\r\nTransfer-Encoding: , \t,\r\n");
    }

    private static void testChunkedLastInMultiLineTransferEncoding(String transferEncodingHeaders) {
        String requestStr = "GET /some/path HTTP/1.1\r\n" +
                transferEncodingHeaders +
                "Host: netty.io\r\n\r\n" +
                "0\r\n\r\n";
        DecoderEmbedder<Object> embedder = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        embedder.offer(ChannelBuffers.copiedBuffer(requestStr, CharsetUtil.US_ASCII));

        HttpRequest request = (HttpRequest) embedder.poll();
        assertNotNull(request);
        assertTrue(request.isChunked());
        assertEquals(2, request.getHeaders(HttpHeaders.Names.TRANSFER_ENCODING).size());
        HttpChunk chunk = (HttpChunk) embedder.poll();
        assertNotNull(chunk);
        assertTrue(chunk.isLast());
        assertNull(embedder.poll());
    }

    @Test
    public void testChunkedLastInCommaSeparatedTransferEncodingIsDecodedAsChunked() {
        // Before the fix, 'gzip, chunked' was not recognized as chunked at all: the request was
        // treated as having no body and the chunked body was parsed as a second (smuggled) request.
        String requestStr = "POST /some/path HTTP/1.1\r\n" +
                "Transfer-Encoding: gzip, chunked\r\n" +
                "Host: netty.io\r\n\r\n" +
                "5\r\nhello\r\n" +
                "0\r\n\r\n";
        DecoderEmbedder<Object> embedder = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        embedder.offer(ChannelBuffers.copiedBuffer(requestStr, CharsetUtil.US_ASCII));

        HttpRequest request = (HttpRequest) embedder.poll();
        assertNotNull(request);
        assertTrue(request.isChunked());
        assertEquals("/some/path", request.getUri());
        HttpChunk chunk = (HttpChunk) embedder.poll();
        assertNotNull(chunk);
        assertFalse(chunk.isLast());
        assertEquals("hello", chunk.getContent().toString(CharsetUtil.US_ASCII));
        HttpChunk lastChunk = (HttpChunk) embedder.poll();
        assertNotNull(lastChunk);
        assertTrue(lastChunk.isLast());
        assertNull(embedder.poll());
    }

    // Regression: the chunked-must-be-last check must not be gated on the protocol version.
    @Test
    public void testChunkedNotLastInTransferEncodingHttp10() {
        String requestStr = "GET /some/path HTTP/1.0\r\n" +
                "Transfer-Encoding: chunked, identity\r\n" +
                "Content-Length: 1\r\n" +
                "Host: netty.io\r\n\r\n" +
                "a";
        testInvalidHeaders0(requestStr);
    }

    // Companion to the test above: confirms the fix isn't tied to identity being a no-op
    // by using a real trailing encoding (gzip) instead.
    @Test
    public void testChunkedNotLastInTransferEncodingHttp10NonNoOpEncoding() {
        String requestStr = "GET /some/path HTTP/1.0\r\n" +
                "Transfer-Encoding: chunked, gzip\r\n" +
                "Content-Length: 1\r\n" +
                "Host: netty.io\r\n\r\n" +
                "a";
        testInvalidHeaders0(requestStr);
    }

    @Test
    public void testResponseChunkedNotLastInTransferEncoding() {
        String responseStr = "HTTP/1.1 200 OK\r\n" +
                "Transfer-Encoding: chunked, gzip\r\n\r\n" +
                "0\r\n\r\n";
        testInvalidResponseHeaders0(ChannelBuffers.copiedBuffer(responseStr, CharsetUtil.US_ASCII));
    }

    @Test
    public void testResponseWithNonChunkedTransferEncodingIsAccepted() {
        // Unlike requests, responses may still be framed by closing the connection.
        String responseStr = "HTTP/1.1 200 OK\r\n" +
                "Connection: close\r\n" +
                "Transfer-Encoding: gzip\r\n\r\n" +
                "abc";
        DecoderEmbedder<Object> embedder = new DecoderEmbedder<Object>(new HttpResponseDecoder());
        embedder.offer(ChannelBuffers.copiedBuffer(responseStr, CharsetUtil.US_ASCII));
        HttpResponse response = (HttpResponse) embedder.poll();
        assertNotNull(response);
        assertEquals("gzip", response.getHeader(HttpHeaders.Names.TRANSFER_ENCODING));
        HttpChunk chunk = (HttpChunk) embedder.poll();
        assertNotNull(chunk);
        assertEquals("abc", chunk.getContent().toString(CharsetUtil.US_ASCII));
    }

    @Test
    public void testContentLengthHeaderWithPositiveSign() {
        String requestStr = "GET /some/path HTTP/1.1\r\n" +
                "Content-Length: +1\r\n\r\n" +
                "b";
        testInvalidHeaders0(requestStr);
    }

    @Test
    public void testContentLengthHeaderWithNegativeSign() {
        String requestStr = "GET /some/path HTTP/1.1\r\n" +
                "Content-Length: -1\r\n\r\n";
        testInvalidHeaders0(requestStr);
    }

    @Test
    public void testContentLengthHeaderWithNegativeValue() {
        String requestStr = "GET /some/path HTTP/1.1\r\n" +
                "Content-Length: -10\r\n\r\n";
        testInvalidHeaders0(requestStr);
    }

    @Test
    public void testMultipleContentLengthHeadersSameValue() {
        // When allowDuplicateContentLengths is false (default), even identical values should be rejected
        String requestStr = "GET /some/path HTTP/1.1\r\n" +
                "Content-Length: 0\r\n" +
                "Content-Length: 0\r\n\r\n";
        testInvalidHeaders0(requestStr);
    }

    @Test
    public void testMultipleContentLengthHeadersSameValueWithComma() {
        // When allowDuplicateContentLengths is false (default), even identical comma-separated values should be rejected
        String requestStr = "GET /some/path HTTP/1.1\r\n" +
                "Content-Length: 0, 0\r\n\r\n";
        testInvalidHeaders0(requestStr);
    }

    // ---------------------------------------------------------------------
    // GHSA-wx5j-54mm-rqqq: header names must be bracketed by OWS only.
    // The decoder used to silently strip every Character.isWhitespace char,
    // which let an attacker smuggle control characters around a header name.
    // The strict OWS check now rejects 0x0c (FF) and 0x1c-0x1f (FS/GS/RS/US)
    // both before the name and between the name and the colon.
    // ---------------------------------------------------------------------

    @Test
    public void testRequestHeaderNameStartsWithControlChar1c() {
        testRequestHeaderNameStartsWithControlChar(0x1c);
    }

    @Test
    public void testRequestHeaderNameStartsWithControlChar1d() {
        testRequestHeaderNameStartsWithControlChar(0x1d);
    }

    @Test
    public void testRequestHeaderNameStartsWithControlChar1e() {
        testRequestHeaderNameStartsWithControlChar(0x1e);
    }

    @Test
    public void testRequestHeaderNameStartsWithControlChar1f() {
        testRequestHeaderNameStartsWithControlChar(0x1f);
    }

    @Test
    public void testRequestHeaderNameStartsWithControlChar0c() {
        testRequestHeaderNameStartsWithControlChar(0x0c);
    }

    private static void testRequestHeaderNameStartsWithControlChar(int controlChar) {
        ChannelBuffer requestBuffer = ChannelBuffers.dynamicBuffer();
        requestBuffer.writeBytes("GET /some/path HTTP/1.1\r\nHost: netty.io\r\n".getBytes(CharsetUtil.US_ASCII));
        requestBuffer.writeByte(controlChar);
        requestBuffer.writeBytes("Transfer-Encoding: chunked\r\n\r\n".getBytes(CharsetUtil.US_ASCII));
        testInvalidRequestHeaders0(requestBuffer);
    }

    @Test
    public void testRequestHeaderNameEndsWithControlChar1c() {
        testRequestHeaderNameEndsWithControlChar(0x1c);
    }

    @Test
    public void testRequestHeaderNameEndsWithControlChar1d() {
        testRequestHeaderNameEndsWithControlChar(0x1d);
    }

    @Test
    public void testRequestHeaderNameEndsWithControlChar1e() {
        testRequestHeaderNameEndsWithControlChar(0x1e);
    }

    @Test
    public void testRequestHeaderNameEndsWithControlChar1f() {
        testRequestHeaderNameEndsWithControlChar(0x1f);
    }

    @Test
    public void testRequestHeaderNameEndsWithControlChar0c() {
        testRequestHeaderNameEndsWithControlChar(0x0c);
    }

    private static void testRequestHeaderNameEndsWithControlChar(int controlChar) {
        ChannelBuffer requestBuffer = ChannelBuffers.dynamicBuffer();
        requestBuffer.writeBytes("GET /some/path HTTP/1.1\r\nHost: netty.io\r\n".getBytes(CharsetUtil.US_ASCII));
        requestBuffer.writeBytes("Transfer-Encoding".getBytes(CharsetUtil.US_ASCII));
        requestBuffer.writeByte(controlChar);
        requestBuffer.writeBytes(": chunked\r\n\r\n".getBytes(CharsetUtil.US_ASCII));
        testInvalidRequestHeaders0(requestBuffer);
    }

    @Test
    public void testResponseHeaderNameStartsWithControlChar1c() {
        testResponseHeaderNameStartsWithControlChar(0x1c);
    }

    @Test
    public void testResponseHeaderNameStartsWithControlChar1d() {
        testResponseHeaderNameStartsWithControlChar(0x1d);
    }

    @Test
    public void testResponseHeaderNameStartsWithControlChar1e() {
        testResponseHeaderNameStartsWithControlChar(0x1e);
    }

    @Test
    public void testResponseHeaderNameStartsWithControlChar1f() {
        testResponseHeaderNameStartsWithControlChar(0x1f);
    }

    @Test
    public void testResponseHeaderNameStartsWithControlChar0c() {
        testResponseHeaderNameStartsWithControlChar(0x0c);
    }

    private static void testResponseHeaderNameStartsWithControlChar(int controlChar) {
        ChannelBuffer responseBuffer = ChannelBuffers.dynamicBuffer();
        responseBuffer.writeBytes("HTTP/1.1 200 OK\r\nHost: netty.io\r\n".getBytes(CharsetUtil.US_ASCII));
        responseBuffer.writeByte(controlChar);
        responseBuffer.writeBytes("Transfer-Encoding: chunked\r\n\r\n".getBytes(CharsetUtil.US_ASCII));
        testInvalidResponseHeaders0(responseBuffer);
    }

    @Test
    public void testResponseHeaderNameEndsWithControlChar1c() {
        testResponseHeaderNameEndsWithControlChar(0x1c);
    }

    @Test
    public void testResponseHeaderNameEndsWithControlChar1d() {
        testResponseHeaderNameEndsWithControlChar(0x1d);
    }

    @Test
    public void testResponseHeaderNameEndsWithControlChar1e() {
        testResponseHeaderNameEndsWithControlChar(0x1e);
    }

    @Test
    public void testResponseHeaderNameEndsWithControlChar1f() {
        testResponseHeaderNameEndsWithControlChar(0x1f);
    }

    @Test
    public void testResponseHeaderNameEndsWithControlChar0c() {
        testResponseHeaderNameEndsWithControlChar(0x0c);
    }

    private static void testResponseHeaderNameEndsWithControlChar(int controlChar) {
        ChannelBuffer responseBuffer = ChannelBuffers.dynamicBuffer();
        responseBuffer.writeBytes("HTTP/1.1 200 OK\r\nHost: netty.io\r\n".getBytes(CharsetUtil.US_ASCII));
        responseBuffer.writeBytes("Transfer-Encoding".getBytes(CharsetUtil.US_ASCII));
        responseBuffer.writeByte(controlChar);
        responseBuffer.writeBytes(": chunked\r\n\r\n".getBytes(CharsetUtil.US_ASCII));
        testInvalidResponseHeaders0(responseBuffer);
    }

    // ---------------------------------------------------------------------
    // CVE-2019-16869: no whitespace is allowed between a header field-name and
    // the colon (RFC 7230 section 3.2.4). For requests this must be rejected
    // (400 Bad Request); for responses the whitespace is silently skipped so
    // that interop with non-compliant servers is preserved.
    // Backport of netty/netty@39cafcb (issue #9571 / PR #9585).
    // ---------------------------------------------------------------------

    @Test
    public void testWhitespaceInRequestHeaderName() {
        String requestStr = "GET /some/path HTTP/1.1\r\n" +
                "Transfer-Encoding : chunked\r\n" +
                "Host: netty.io\r\n\r\n";
        testInvalidRequestHeaders0(ChannelBuffers.copiedBuffer(requestStr, CharsetUtil.US_ASCII));
    }

    @Test
    public void testWhitespaceInResponseHeaderName() {
        String responseStr = "HTTP/1.1 200 OK\r\n" +
                "Transfer-Encoding : chunked\r\n" +
                "Host: netty.io\r\n\r\n";
        DecoderEmbedder<Object> embedder = new DecoderEmbedder<Object>(new HttpResponseDecoder());
        embedder.offer(ChannelBuffers.copiedBuffer(responseStr, CharsetUtil.US_ASCII));
        HttpResponse response = (HttpResponse) embedder.poll();
        assertNotNull(response);
        assertEquals(HttpHeaders.Values.CHUNKED,
                response.getHeader(HttpHeaders.Names.TRANSFER_ENCODING));
        assertEquals("netty.io", response.getHeader(HttpHeaders.Names.HOST));
    }

    // ---------------------------------------------------------------------
    // CVE-2026-93566 / CVE-2026-93574: a chunk size line is only a run of hex
    // digits, optionally followed by BWS (SP / HTAB) and ';' chunk-extensions
    // (RFC 9112 7.1). Leading/trailing whitespace, extra tokens after the
    // whitespace and control characters used to be silently truncated, so the
    // decoder framed the body differently than a front-end proxy and a second,
    // smuggled message could be injected. Such lines must now be rejected.
    // Backport of netty/netty@161f9ade.
    // ---------------------------------------------------------------------

    @Test
    public void testRequestChunkSizeEmpty() {
        testRequestChunkSizeLineRejected("");
    }

    @Test
    public void testRequestChunkSizeTrailingWhitespace() {
        testRequestChunkSizeLineRejected("5 ");
    }

    @Test
    public void testRequestChunkSizeLeadingWhitespace() {
        testRequestChunkSizeLineRejected(" 5");
    }

    @Test
    public void testRequestChunkSizeWhitespaceThenHexDigit() {
        testRequestChunkSizeLineRejected("5 c");
    }

    @Test
    public void testRequestChunkSizeWhitespaceThenToken() {
        testRequestChunkSizeLineRejected("5 x");
    }

    @Test
    public void testRequestChunkSizeWhitespaceThenHexDigitAndExtension() {
        testRequestChunkSizeLineRejected("5 c;foo=bar");
    }

    @Test
    public void testRequestChunkSizeLeadingWhitespaceThenHexDigit() {
        testRequestChunkSizeLineRejected("  5 c");
    }

    @Test
    public void testRequestChunkSizeLeadingWhitespaceThenToken() {
        testRequestChunkSizeLineRejected("  5 x");
    }

    @Test
    public void testRequestChunkSizeLeadingWhitespaceThenHexDigitAndExtension() {
        testRequestChunkSizeLineRejected("  5 c;foo=bar");
    }

    @Test
    public void testRequestChunkSizeWithNul() {
        testRequestChunkSizeLineRejected("5" + (char) 0x00 + "c");
    }

    @Test
    public void testRequestChunkSizeWithVerticalTab() {
        testRequestChunkSizeLineRejected("5" + (char) 0x0b + "c");
    }

    @Test
    public void testRequestChunkSizeWithFormFeed() {
        testRequestChunkSizeLineRejected("5" + (char) 0x0c);
    }

    @Test
    public void testRequestChunkSizeWithLeadingControlChar() {
        testRequestChunkSizeLineRejected((char) 0x01 + "5");
    }

    @Test
    public void testRequestChunkSizeWithBareCrThenHexDigit() {
        // Used to be read as "5": the bare CR and the byte following it were dropped.
        testRequestChunkSizeLineRejected("5\rc");
    }

    @Test
    public void testRequestChunkSizeWithTrailingBareCr() {
        testRequestChunkSizeLineRejected("5\r");
    }

    @Test
    public void testRequestChunkSizeWithPlusSign() {
        testRequestChunkSizeLineRejected("+5");
    }

    @Test
    public void testResponseChunkSizeEmpty() {
        testResponseChunkSizeLineRejected("");
    }

    @Test
    public void testResponseChunkSizeTrailingWhitespace() {
        testResponseChunkSizeLineRejected("5 ");
    }

    @Test
    public void testResponseChunkSizeLeadingWhitespace() {
        testResponseChunkSizeLineRejected(" 5");
    }

    @Test
    public void testResponseChunkSizeWhitespaceThenHexDigit() {
        testResponseChunkSizeLineRejected("5 c");
    }

    @Test
    public void testResponseChunkSizeWhitespaceThenToken() {
        testResponseChunkSizeLineRejected("5 x");
    }

    @Test
    public void testResponseChunkSizeWhitespaceThenHexDigitAndExtension() {
        testResponseChunkSizeLineRejected("5 c;foo=bar");
    }

    @Test
    public void testResponseChunkSizeLeadingWhitespaceThenHexDigit() {
        testResponseChunkSizeLineRejected("  5 c");
    }

    @Test
    public void testResponseChunkSizeLeadingWhitespaceThenToken() {
        testResponseChunkSizeLineRejected("  5 x");
    }

    @Test
    public void testResponseChunkSizeLeadingWhitespaceThenHexDigitAndExtension() {
        testResponseChunkSizeLineRejected("  5 c;foo=bar");
    }

    @Test
    public void testResponseChunkSizeWithNul() {
        testResponseChunkSizeLineRejected("5" + (char) 0x00 + "c");
    }

    @Test
    public void testResponseChunkSizeWithBareCrThenHexDigit() {
        testResponseChunkSizeLineRejected("5\rc");
    }

    @Test
    public void testRequestChunkSizeWithBadWhitespaceBeforeExtension() {
        testRequestChunkSizeLineAccepted("5 \t;foo=bar");
    }

    @Test
    public void testRequestChunkSizeWithExtension() {
        testRequestChunkSizeLineAccepted("5;foo=bar");
    }

    @Test
    public void testRequestChunkSizeWithLeadingZeros() {
        testRequestChunkSizeLineAccepted("00005");
    }

    @Test
    public void testRequestChunkSizeUpperAndLowerCaseHex() {
        String requestStr = "POST / HTTP/1.1\r\n" +
                "Host: example\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "a\r\n" +
                "0123456789\r\n" +
                "B\r\n" +
                "0123456789A\r\n" +
                "0\r\n" +
                "\r\n";
        DecoderEmbedder<Object> embedder = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        embedder.offer(ChannelBuffers.copiedBuffer(requestStr, CharsetUtil.US_ASCII));

        HttpRequest request = (HttpRequest) embedder.poll();
        assertNotNull(request);
        assertTrue(request.isChunked());
        HttpChunk chunk = (HttpChunk) embedder.poll();
        assertEquals("0123456789", chunk.getContent().toString(CharsetUtil.US_ASCII));
        chunk = (HttpChunk) embedder.poll();
        assertEquals("0123456789A", chunk.getContent().toString(CharsetUtil.US_ASCII));
        chunk = (HttpChunk) embedder.poll();
        assertTrue(chunk.isLast());
        assertNull(embedder.poll());
    }

    @Test
    public void testResponseChunkSizeWithBadWhitespaceBeforeExtension() {
        String responseStr = "HTTP/1.1 200 OK\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "5\t ;foo=bar\r\n" +
                "hello\r\n" +
                "0\r\n" +
                "\r\n";
        DecoderEmbedder<Object> embedder = new DecoderEmbedder<Object>(new HttpResponseDecoder());
        embedder.offer(ChannelBuffers.copiedBuffer(responseStr, CharsetUtil.US_ASCII));

        HttpResponse response = (HttpResponse) embedder.poll();
        assertNotNull(response);
        assertTrue(response.isChunked());
        HttpChunk chunk = (HttpChunk) embedder.poll();
        assertEquals("hello", chunk.getContent().toString(CharsetUtil.US_ASCII));
        chunk = (HttpChunk) embedder.poll();
        assertTrue(chunk.isLast());
        assertNull(embedder.poll());
    }

    private static void testRequestChunkSizeLineRejected(String chunkSizeLine) {
        String requestStr = "POST / HTTP/1.1\r\n" +
                "Host: example\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                chunkSizeLine + "\r\n" +
                "GPOST\r\n" +
                "0\r\n" +
                "\r\n" +
                "GET /smuggled HTTP/1.1\r\n" +
                "Host: example\r\n" +
                "\r\n";
        DecoderEmbedder<Object> embedder = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        try {
            embedder.offer(ChannelBuffers.copiedBuffer(requestStr, CharsetUtil.US_ASCII));
            fail("Expected CodecEmbedderException");
        } catch (CodecEmbedderException e) {
            // The malformed chunk size line must be rejected, not truncated at the whitespace.
            assertTrue("expected NumberFormatException but was: " + e.getCause(),
                    e.getCause() instanceof NumberFormatException);
            assertTrue(e.getCause().getMessage(), e.getCause().getMessage().contains("chunk size"));
        }

        // The request headers parse fine.
        HttpRequest request = (HttpRequest) embedder.poll();
        assertNotNull(request);
        assertEquals(HttpVersion.HTTP_1_1, request.getProtocolVersion());
        assertEquals(HttpMethod.POST, request.getMethod());
        assertTrue(request.isChunked());

        // Nothing after the failed chunk may be surfaced as content or as a second, smuggled request.
        assertNull(embedder.poll());
    }

    private static void testResponseChunkSizeLineRejected(String chunkSizeLine) {
        String responseStr = "HTTP/1.1 200 OK\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                chunkSizeLine + "\r\n" + // malformed chunk size
                "GPOST\r\n" +
                "0\r\n" +
                "\r\n" +
                "HTTP/1.1 200 smuggled\r\n" +
                "Host: example\r\n" +
                "\r\n";
        DecoderEmbedder<Object> embedder = new DecoderEmbedder<Object>(new HttpResponseDecoder());
        try {
            embedder.offer(ChannelBuffers.copiedBuffer(responseStr, CharsetUtil.US_ASCII));
            fail("Expected CodecEmbedderException");
        } catch (CodecEmbedderException e) {
            // The malformed chunk size line must be rejected, not truncated at the whitespace.
            assertTrue("expected NumberFormatException but was: " + e.getCause(),
                    e.getCause() instanceof NumberFormatException);
            assertTrue(e.getCause().getMessage(), e.getCause().getMessage().contains("chunk size"));
        }

        // The response headers parse fine.
        HttpResponse response = (HttpResponse) embedder.poll();
        assertNotNull(response);
        assertEquals(HttpVersion.HTTP_1_1, response.getProtocolVersion());
        assertEquals(HttpResponseStatus.OK, response.getStatus());
        assertTrue(response.isChunked());

        // Nothing after the failed chunk may be surfaced as content or as a second, smuggled response.
        assertNull(embedder.poll());
    }

    private static void testRequestChunkSizeLineAccepted(String chunkSizeLine) {
        String requestStr = "POST / HTTP/1.1\r\n" +
                "Host: example\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                chunkSizeLine + "\r\n" +
                "hello\r\n" +
                "0\r\n" +
                "\r\n";
        DecoderEmbedder<Object> embedder = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        embedder.offer(ChannelBuffers.copiedBuffer(requestStr, CharsetUtil.US_ASCII));

        HttpRequest request = (HttpRequest) embedder.poll();
        assertNotNull(request);
        assertTrue(request.isChunked());
        HttpChunk chunk = (HttpChunk) embedder.poll();
        assertNotNull(chunk);
        assertFalse(chunk.isLast());
        assertEquals("hello", chunk.getContent().toString(CharsetUtil.US_ASCII));
        HttpChunk lastChunk = (HttpChunk) embedder.poll();
        assertNotNull(lastChunk);
        assertTrue(lastChunk.isLast());
        assertNull(embedder.poll());
    }

    private static void testInvalidHeaders0(String requestStr) {
        testInvalidRequestHeaders0(ChannelBuffers.copiedBuffer(requestStr, CharsetUtil.US_ASCII));
    }

    private static void testInvalidRequestHeaders0(ChannelBuffer requestBuffer) {
        DecoderEmbedder<Object> embedder = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        try {
            embedder.offer(requestBuffer);
            fail("Expected CodecEmbedderException");
        } catch (CodecEmbedderException e) {
            assertTrue(e.getCause() instanceof IllegalArgumentException);
        }
    }

    private static void testInvalidResponseHeaders0(ChannelBuffer responseBuffer) {
        DecoderEmbedder<Object> embedder = new DecoderEmbedder<Object>(new HttpResponseDecoder());
        try {
            embedder.offer(responseBuffer);
            fail("Expected CodecEmbedderException");
        } catch (CodecEmbedderException e) {
            assertTrue(e.getCause() instanceof IllegalArgumentException);
        }
    }
}
