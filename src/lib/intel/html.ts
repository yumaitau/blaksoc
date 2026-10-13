import sanitizeHtml from "sanitize-html";

/** Feed HTML is untrusted, including content stored before this renderer was introduced. */
export function sanitizeIntelHtml(html: string) {
  return sanitizeHtml(html, {
    allowedTags: ["p", "br", "div", "span", "strong", "b", "em", "i", "u", "s", "blockquote", "pre", "code", "ul", "ol", "li", "h2", "h3", "h4", "h5", "h6", "hr", "a", "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption"],
    allowedAttributes: { a: ["href", "title", "target", "rel"], th: ["colspan", "rowspan", "scope"], td: ["colspan", "rowspan"] },
    allowedSchemes: ["https", "http"],
    allowProtocolRelative: false,
    disallowedTagsMode: "discard",
    // Drop active/embedded content with its children, not just its outer tag.
    nonTextTags: ["script", "style", "textarea", "option", "noscript", "iframe", "object", "embed", "svg", "math", "template"],
    transformTags: {
      a: (_tag, attributes) => {
        const href = attributes.href ?? "";
        // Do not let imported content navigate to local app actions or inherit its origin.
        const safe = /^https?:\/\//i.test(href) && !/[\u0000-\u0020\u007f\\]/.test(href);
        return { tagName: "a", attribs: {
          ...(safe ? { href, target: "_blank", rel: "noopener noreferrer nofollow" } : {}),
          ...(attributes.title ? { title: attributes.title } : {}),
        } };
      },
    },
  });
}
