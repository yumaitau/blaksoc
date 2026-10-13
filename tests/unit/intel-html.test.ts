import { describe, expect, it } from "vitest";
import { sanitizeIntelHtml } from "@/lib/intel/html";

describe("untrusted threat-intel HTML", () => {
  it("preserves paragraphs, lists, emphasis, code and tables", () => {
    const html = '<h3>Advisory</h3><p>A <strong>critical</strong> flaw.</p><ul><li>Patch now</li></ul><pre><code>&lt;payload&gt;</code></pre><table><tbody><tr><th scope="row">CVE</th><td>CVE-2026-1234</td></tr></tbody></table>';
    expect(sanitizeIntelHtml(html)).toBe(html);
    expect(sanitizeIntelHtml("Use A & B; risk < 5.")).toBe("Use A &amp; B; risk &lt; 5.");
  });

  it("strips active content, trackers, event handlers and CSS", () => {
    const result = sanitizeIntelHtml('<script>alert(1)</script><style>body{display:none}</style><p onclick="alert(1)" style="position:fixed" id="app" class="overlay">Safe</p><img src="https://tracker.example/pixel" onerror="alert(1)"><iframe srcdoc="<script>alert(1)</script>">Bad</iframe><form action="/api/delete"><input name="x">Text</form>');
    expect(result).toBe("<p>Safe</p>Text");
  });

  it.each([
    "javascript:alert(1)", "jav&#x61;script:alert(1)", "java&#x09;script:alert(1)",
    "data:text/html,boom", "vbscript:boom", "//evil.example", "/api/auth/logout", "https:\\evil.example", "mailto:a@example.com",
  ])("removes unsafe link %s while retaining its text", (href) => {
    expect(sanitizeIntelHtml(`<a href="${href}" target="_self" ping="https://tracker.example">Read</a>`)).toBe("<a>Read</a>");
  });

  it("isolates external links and strips navigation/tracking attributes", () => {
    expect(sanitizeIntelHtml('<a href="https://example.com/report?a=1&amp;b=2" target="_top" rel="opener" ping="https://tracker.example" download>Read</a>')).toBe('<a href="https://example.com/report?a=1&amp;b=2" target="_blank" rel="noopener noreferrer nofollow">Read</a>');
  });

  it.each([
    '<svg><a xlink:href="javascript:alert(1)">bad</a></svg><p>Safe</p>',
    '<math><mtext><img src=x onerror=alert(1)></mtext></math><p>Safe</p>',
    '<template><img src=x onerror=alert(1)></template><p>Safe</p>',
    '<textarea><img src=x onerror=alert(1)></textarea><p>Safe</p>',
    '<option><img src=x onerror=alert(1)></option><p>Safe</p>',
  ])("drops parser edge cases with their children", (html) => {
    const result = sanitizeIntelHtml(html);
    expect(result).toBe("<p>Safe</p>");
    expect(sanitizeIntelHtml(result)).toBe(result);
  });
});
