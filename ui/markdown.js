import { marked } from 'marked';
import DOMPurify from 'dompurify';

export function validateOverview(text) {
  if (new TextEncoder().encode(text).length > 64 * 1024)
    throw new Error('Overview must be at most 64 KiB (UTF-8).');
  return text;
}

// Restrict embedded HTML to document content and remove active URLs and UI attributes.
export function renderMarkdown(text, target) {
  const fragment = DOMPurify.sanitize(marked.parse(validateOverview(text), { gfm: true, async: false }), {
    ALLOWED_TAGS: ['h1','h2','h3','h4','h5','h6','p','br','hr','strong','b','em','i','del','s',
      'blockquote','pre','code','ul','ol','li','a','img','table','thead','tbody','tr','th','td','details','summary'],
    ALLOWED_ATTR: ['href','src','alt','title','start','align','open'],
    ALLOW_DATA_ATTR: false, RETURN_DOM_FRAGMENT: true,
  });
  for (const link of fragment.querySelectorAll('a')) {
    const href = link.getAttribute('href') || '';
    // A binary upload does not provide a base URL for repository-relative paths.
    if (!/^(https?:\/\/|mailto:)/i.test(href)) link.removeAttribute('href');
    else link.setAttribute('rel', 'nofollow noopener noreferrer');
  }
  for (const img of fragment.querySelectorAll('img')) {
    if (!/^https:\/\//i.test(img.getAttribute('src') || '')) {
      img.replaceWith(document.createTextNode(img.getAttribute('alt') || 'Image'));
    } else {
      img.setAttribute('loading', 'lazy');
      img.setAttribute('referrerpolicy', 'no-referrer');
    }
  }
  target.replaceChildren(fragment);
  if (!text.trim()) {
    const empty = document.createElement('p');
    empty.className = 'quiet';
    empty.textContent = 'No overview yet. The package owner can add documentation here.';
    target.append(empty);
  }
}

export function markdownEditor(root) {
  const input = root.querySelector('textarea'), preview = root.querySelector('.markdown-preview');
  const buttons = root.querySelectorAll('[data-editor-mode]');
  function show(mode) {
    if (mode === 'preview') {
      try { renderMarkdown(input.value, preview); }
      catch (error) { preview.textContent = error.message; }
    }
    input.hidden = mode === 'preview';
    preview.hidden = mode !== 'preview';
    for (const b of buttons) b.setAttribute('aria-pressed', String(b.dataset.editorMode === mode));
  }
  for (const b of buttons) b.addEventListener('click', () => show(b.dataset.editorMode));
  return () => show('write');
}
