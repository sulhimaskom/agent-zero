/**
 * HTML Sanitization Utility
 * Provides XSS protection by sanitizing HTML content before rendering
 * 
 * Uses DOMPurify if available, otherwise falls back to basic sanitization
 */

// Try to use DOMPurify if available (best approach)
let DOMPurify = null;
try {
  DOMPurify = window.DOMPurify;
} catch (e) {
  // DOMPurify not available, will use fallback
}

/**
 * Tags that are safe to render from markdown
 */
const SAFE_TAGS = [
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'p', 'br', 'hr',
  'strong', 'b', 'em', 'i', 'u', 's', 'strike', 'del',
  'ul', 'ol', 'li',
  'a', 'img',
  'blockquote', 'pre', 'code', 'span',
  'table', 'thead', 'tbody', 'tr', 'th', 'td',
  'div', 'section', 'article',
  'latex'  // Custom tag for KaTeX
];

/**
 * Attributes that are safe to keep
 */
const SAFE_ATTRS = [
  'href', 'src', 'alt', 'title', 'class', 'id',
  'width', 'height', 'style',
  'target', 'rel',
  'colspan', 'rowspan',
  'data-lang'  // For code blocks
];

/**
 * Dangerous patterns that should be stripped
 */
const DANGEROUS_PATTERNS = [
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
  /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
  /<embed\b[^>]*>/gi,
  /<link\b[^>]*>/gi,
  /<form\b[^<]*(?:(?!<\/form>)<[^<]*)*<\/form>/gi,
  /on\w+\s*=\s*["'][^"']*["']/gi,  // Event handlers
  /javascript:\s*/gi,  // JavaScript URLs
  /data:\s*text\/html/gi  // Data URLs
];

/**
 * Sanitize HTML content to prevent XSS attacks
 * 
 * @param {string} html - HTML string to sanitize
 * @returns {string} Sanitized HTML string
 */
export function sanitizeHTML(html) {
  if (!html || typeof html !== 'string') {
    return '';
  }

  // Use DOMPurify if available (preferred)
  if (DOMPurify) {
    return DOMPurify.sanitize(html, {
      ALLOWED_TAGS: SAFE_TAGS,
      ALLOWED_ATTR: SAFE_ATTRS,
      FORBID_TAGS: ['style', 'link'],
      FORBID_ATTR: ['style']
    });
  }

  // Fallback: Basic sanitization
  return basicSanitize(html);
}

/**
 * Basic HTML sanitization fallback
 * Strips dangerous tags and attributes while preserving safe formatting
 * 
 * @param {string} html - HTML string to sanitize
 * @returns {string} Sanitized HTML string
 */
function basicSanitize(html) {
  let result = html;

  // First, strip dangerous patterns
  for (const pattern of DANGEROUS_PATTERNS) {
    result = result.replace(pattern, '');
  }

  // Then, parse and whitelist tags
  const parser = new DOMParser();
  const doc = parser.parseFromString(result, 'text/html');
  
  // Walk the DOM and remove disallowed tags
  const walker = document.createTreeWalker(
    doc.body,
    NodeFilter.SHOW_ELEMENT,
    null,
    false
  );

  const nodesToRemove = [];
  let node;
  while (node = walker.nextNode()) {
    const tagName = node.tagName.toLowerCase();
    if (!SAFE_TAGS.includes(tagName)) {
      // Replace with text content for non-safe tags
      nodesToRemove.push(node);
    } else {
      // Remove disallowed attributes from safe tags
      const attrsToRemove = [];
      for (const attr of node.attributes) {
        if (!SAFE_ATTRS.includes(attr.name.toLowerCase())) {
          attrsToRemove.push(attr.name);
        }
      }
      attrsToRemove.forEach(attr => node.removeAttribute(attr));
    }
  }

  // Remove disallowed nodes (replace with text)
  nodesToRemove.forEach(node => {
    const text = document.createTextNode(node.textContent);
    node.parentNode.replaceChild(text, node);
  });

  return doc.body.innerHTML;
}

/**
 * Check if a string contains potentially dangerous HTML
 * Useful for validation before rendering
 * 
 * @param {string} str - String to check
 * @returns {boolean} True if potentially dangerous
 */
export function containsDangerousHTML(str) {
  if (!str || typeof str !== 'string') {
    return false;
  }

  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(str)) {
      return true;
    }
  }

  return false;
}
