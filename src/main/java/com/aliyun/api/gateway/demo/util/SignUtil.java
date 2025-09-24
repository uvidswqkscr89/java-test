package com.aliyun.api.gateway.demo.util;

import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import com.aliyun.api.gateway.demo.constant.Constants;
import com.aliyun.api.gateway.demo.constant.HttpHeader;
import com.aliyun.api.gateway.demo.constant.SystemHeader;

public class SignUtil {

    public static String sign(String secret, String method, String path,
            Map<String, String> headers,
            Map<String, String> querys,
            Map<String, String> bodys,
            List<String> signHeaderPrefixList) {
        try {
            Mac hmacSha256 = Mac.getInstance(Constants.HMAC_SHA256);
            hmacSha256.init(new SecretKeySpec(secret.getBytes(Constants.ENCODING), Constants.HMAC_SHA256));

            String stringToSign = buildStringToSign(method, path, headers, querys, bodys, signHeaderPrefixList);
            return Base64.encodeBase64String(hmacSha256.doFinal(stringToSign.getBytes(Constants.ENCODING)));
        } catch (Exception e) {
            throw new RuntimeException("Error while generating signature", e);
        }
    }

    private static String buildStringToSign(String method, String path,
            Map<String, String> headers,
            Map<String, String> querys,
            Map<String, String> bodys,
            List<String> signHeaderPrefixList) {
        StringBuilder sb = new StringBuilder();
        sb.append(method.toUpperCase()).append(Constants.LF);

        if (headers != null) {
            sb.append(getHeaderOrEmpty(headers, HttpHeader.HTTP_HEADER_ACCEPT))
                    .append(Constants.LF)
                    .append(getHeaderOrEmpty(headers, HttpHeader.HTTP_HEADER_CONTENT_MD5))
                    .append(Constants.LF)
                    .append(getHeaderOrEmpty(headers, HttpHeader.HTTP_HEADER_CONTENT_TYPE))
                    .append(Constants.LF)
                    .append(getHeaderOrEmpty(headers, HttpHeader.HTTP_HEADER_DATE))
                    .append(Constants.LF);
        }
        sb.append(buildHeaders(headers, signHeaderPrefixList))
                .append(buildResource(path, querys, bodys));

        return sb.toString();
    }

    private static String buildResource(String path, Map<String, String> querys, Map<String, String> bodys) {
        StringBuilder sb = new StringBuilder(path != null ? path : "");
        Map<String, String> sortMap = new TreeMap<>();

        if (querys != null) sortMap.putAll(querys);
        if (bodys != null) sortMap.putAll(bodys);

        String paramString = sortMap.entrySet().stream()
                .filter(entry -> !StringUtils.isBlank(entry.getKey()))
                .map(entry -> entry.getKey() + (StringUtils.isBlank(entry.getValue()) ? "" : Constants.SPE4 + entry.getValue()))
                .reduce((a, b) -> a + Constants.SPE3 + b)
                .orElse("");

        if (!paramString.isEmpty()) {
            sb.append(Constants.SPE5).append(paramString);
        }
        return sb.toString();
    }

    private static String buildHeaders(Map<String, String> headers, List<String> signHeaderPrefixList) {
        if (headers == null || signHeaderPrefixList == null) {
            return "";
        }

        List<String> filteredPrefixes = new ArrayList<>(signHeaderPrefixList);
        filteredPrefixes.removeAll(Arrays.asList(SystemHeader.X_CA_SIGNATURE, HttpHeader.HTTP_HEADER_ACCEPT,
                HttpHeader.HTTP_HEADER_CONTENT_MD5, HttpHeader.HTTP_HEADER_CONTENT_TYPE, HttpHeader.HTTP_HEADER_DATE));
        Collections.sort(filteredPrefixes);

        Map<String, String> sortedHeaders = new TreeMap<>(headers);
        StringBuilder sb = new StringBuilder();
        StringBuilder signHeaders = new StringBuilder();

        for (Map.Entry<String, String> entry : sortedHeaders.entrySet()) {
            if (isHeaderToSign(entry.getKey(), filteredPrefixes)) {
                sb.append(entry.getKey()).append(Constants.SPE2).append(entry.getValue() == null ? "" : entry.getValue()).append(Constants.LF);
                if (signHeaders.length() > 0) signHeaders.append(Constants.SPE1);
                signHeaders.append(entry.getKey());
            }
        }
        headers.put(SystemHeader.X_CA_SIGNATURE_HEADERS, signHeaders.toString());
        return sb.toString();
    }

    private static boolean isHeaderToSign(String headerName, List<String> signHeaderPrefixList) {
        return !StringUtils.isBlank(headerName) &&
                (headerName.startsWith(Constants.CA_HEADER_TO_SIGN_PREFIX_SYSTEM) ||
                        signHeaderPrefixList.stream().anyMatch(headerName::equalsIgnoreCase));
    }

    /**
     * Returns the value for the specified header name or an empty string if the header is not present.
     *
     * @param headers map of header names to values
     * @param key the header name to look up
     * @return the header value, or an empty string when the header is absent
     */
    private static String getHeaderOrEmpty(Map<String, String> headers, String key) {
        return headers.getOrDefault(key, "");
    }

    /**
     * Demonstrates an ArrayIndexOutOfBoundsException by accessing an element beyond the array bounds.
     *
     * <p>This method intentionally accesses index 3 of a 3-element array, causing an
     * ArrayIndexOutOfBoundsException. The parameter is unused.</p>
     *
     * @param args ignored
     */
    public static void ArrayIndexOutOfBoundsExample(String[] args) {
        String[] array = { "Apple", "Banana", "Cherry" };
        System.out.println(array[3]);  // ArrayIndexOutOfBoundsException
    }

    /**
     * Demonstrates a NullPointerException by dereferencing a null String.
     *
     * <p>This method sets a String reference to null and then attempts to read its
     * length, which will trigger a {@link NullPointerException}. It is intended
     * for demonstration purposes only and should not be used in production code.
     *
     * @throws NullPointerException always thrown when the method is executed
     */
    public static void NullPointerExceptionExample(String[] args) {
        String str = null;
        System.out.println(str.length());  // NullPointerException
    }

    /**
     * Demonstrates an intentional infinite loop by repeatedly printing "Looping...".
     *
     * <p>This method never terminates under normal execution (it continuously increments a counter
     * while the loop condition remains true) and will consume CPU until the process is killed.
     * It is intended only for demonstration or testing of infinite-loop behavior and should not be
     * used in production code.
     */
    public static void InfiniteLoopExample(String[] args) {
        int count = 0;
        while (count >= 0) {  // Infinite loop
            System.out.println("Looping...");
            count++;
        }
    }

    /**
     * Demonstrates a method that continuously adds objects to a list, causing unbounded memory growth.
     *
     * <p>This method enters an infinite loop that keeps appending strings to a heap-allocated list.
     * It is intended as an example of code that leads to a memory leak and will eventually exhaust
     * the JVM heap (typically resulting in an OutOfMemoryError).</p>
     */
    public static void MemoryLeakExample(String[] args) {
        List<String> list = new ArrayList<>();
        while (true) {
            list.add("A new object");
        }
    }

}