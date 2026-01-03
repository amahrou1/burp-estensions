package burp;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.URL;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private LinkExtractorPanel panel;

    // Store all discovered links: Source URL -> Set of discovered links
    private Map<String, Set<String>> linkMap = new LinkedHashMap<>();
    private Set<String> allLinks = new HashSet<>(); // Global deduplication

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Link Extractor");

        // Create UI panel
        panel = new LinkExtractorPanel(this);

        // Register HTTP listener
        callbacks.registerHttpListener(this);

        // Add custom tab
        callbacks.addSuiteTab(this);

        callbacks.printOutput("Link Extractor loaded successfully!");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // Only process responses
        if (messageIsRequest) {
            return;
        }

        // Check if scope filter is enabled
        if (panel.isScopeFilterEnabled()) {
            if (!callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl())) {
                return;
            }
        }

        try {
            // Get response
            byte[] response = messageInfo.getResponse();
            if (response == null) {
                return;
            }

            // Get source URL
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            URL sourceUrl = requestInfo.getUrl();
            String sourceUrlString = sourceUrl.toString();

            // Extract response body
            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            int bodyOffset = responseInfo.getBodyOffset();
            String responseBody = new String(response, bodyOffset, response.length - bodyOffset);

            // Extract links
            Set<String> extractedLinks = extractLinks(responseBody, sourceUrl);

            if (!extractedLinks.isEmpty()) {
                synchronized (linkMap) {
                    linkMap.putIfAbsent(sourceUrlString, new LinkedHashSet<>());

                    for (String link : extractedLinks) {
                        // Global deduplication check
                        if (!allLinks.contains(link)) {
                            linkMap.get(sourceUrlString).add(link);
                            allLinks.add(link);
                        }
                    }
                }

                // Update UI
                SwingUtilities.invokeLater(() -> panel.updateDisplay());
            }

        } catch (Exception e) {
            callbacks.printError("Error processing response: " + e.getMessage());
        }
    }

    private Set<String> extractLinks(String responseBody, URL sourceUrl) {
        Set<String> links = new HashSet<>();

        // Pattern for absolute URLs (http:// and https://)
        Pattern absoluteUrlPattern = Pattern.compile(
            "(https?://[\\w\\-\\._~:/?#\\[\\]@!$&'()*+,;=%]+)",
            Pattern.CASE_INSENSITIVE
        );

        // Pattern for relative paths and endpoints
        // Matches: "/api/endpoint", "/users/login", "../path", etc.
        Pattern relativePathPattern = Pattern.compile(
            "[\"'`]\\s*([/\\.][\\w\\-\\._~:/?#\\[\\]@!$&()*+,;=%]*?)\\s*[\"'`]",
            Pattern.CASE_INSENSITIVE
        );

        // Pattern for method definitions like Method="GET" "/users/login"
        Pattern methodEndpointPattern = Pattern.compile(
            "(?:method|Method|METHOD)\\s*=\\s*[\"'](?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)[\"']\\s+[\"']([/][\\w\\-\\._~:/?#\\[\\]@!$&()*+,;=%]*)[\"']",
            Pattern.CASE_INSENSITIVE
        );

        // Extract absolute URLs
        Matcher absoluteMatcher = absoluteUrlPattern.matcher(responseBody);
        while (absoluteMatcher.find()) {
            String url = absoluteMatcher.group(1);
            // Clean up trailing punctuation
            url = cleanUrl(url);
            if (isValidUrl(url)) {
                links.add(url);
            }
        }

        // Extract relative paths
        Matcher relativeMatcher = relativePathPattern.matcher(responseBody);
        while (relativeMatcher.find()) {
            String path = relativeMatcher.group(1);
            if (isValidPath(path)) {
                String absoluteUrl = buildAbsoluteUrl(sourceUrl, path);
                if (absoluteUrl != null && isValidUrl(absoluteUrl)) {
                    links.add(absoluteUrl);
                }
            }
        }

        // Extract method-endpoint patterns
        Matcher methodMatcher = methodEndpointPattern.matcher(responseBody);
        while (methodMatcher.find()) {
            String endpoint = methodMatcher.group(1);
            String absoluteUrl = buildAbsoluteUrl(sourceUrl, endpoint);
            if (absoluteUrl != null && isValidUrl(absoluteUrl)) {
                links.add(absoluteUrl);
            }
        }

        return links;
    }

    private String buildAbsoluteUrl(URL sourceUrl, String path) {
        try {
            // Handle relative paths
            if (path.startsWith("/")) {
                // Absolute path - use source URL's protocol, host, port
                return sourceUrl.getProtocol() + "://" + sourceUrl.getHost() +
                       (sourceUrl.getPort() != -1 ? ":" + sourceUrl.getPort() : "") + path;
            } else if (path.startsWith("..")) {
                // Relative path going up - use URL resolution
                URL resolvedUrl = new URL(sourceUrl, path);
                return resolvedUrl.toString();
            } else if (path.startsWith(".")) {
                // Current directory relative path
                URL resolvedUrl = new URL(sourceUrl, path);
                return resolvedUrl.toString();
            }
        } catch (Exception e) {
            // Ignore invalid URLs
        }
        return null;
    }

    private String cleanUrl(String url) {
        // Remove trailing punctuation that might be part of text
        while (url.length() > 0 && ".,;:!?)\"'".indexOf(url.charAt(url.length() - 1)) != -1) {
            url = url.substring(0, url.length() - 1);
        }
        return url;
    }

    private boolean isValidUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }

        // Must start with http:// or https://
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return false;
        }

        // Basic validation
        try {
            new URL(url);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isValidPath(String path) {
        if (path == null || path.trim().isEmpty()) {
            return false;
        }

        // Should start with / or . for relative paths
        if (!path.startsWith("/") && !path.startsWith(".")) {
            return false;
        }

        // Ignore common non-path patterns
        if (path.equals("/") || path.equals("./") || path.equals("../")) {
            return false;
        }

        // Ignore file extensions that are typically not endpoints
        String lower = path.toLowerCase();
        if (lower.endsWith(".jpg") || lower.endsWith(".png") || lower.endsWith(".gif") ||
            lower.endsWith(".css") || lower.endsWith(".ico") || lower.endsWith(".svg") ||
            lower.endsWith(".woff") || lower.endsWith(".woff2") || lower.endsWith(".ttf")) {
            return false;
        }

        return true;
    }

    public Map<String, Set<String>> getLinkMap() {
        synchronized (linkMap) {
            return new LinkedHashMap<>(linkMap);
        }
    }

    public void clearLinks() {
        synchronized (linkMap) {
            linkMap.clear();
            allLinks.clear();
        }
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    @Override
    public String getTabCaption() {
        return "Link Extractor";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }
}
