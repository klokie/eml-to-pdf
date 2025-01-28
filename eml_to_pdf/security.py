"""Security related html sanitization."""

from bs4 import BeautifulSoup


def sanitize_html(html_content: str) -> str:
    """Remove potentially unsafe elements from HTML."""
    soup = BeautifulSoup(html_content, "html.parser")

    # Handle images
    for img in soup.find_all("img"):
        # Skip if img tag is malformed/empty
        if not img or not hasattr(img, "attrs") or not isinstance(img.attrs, dict):
            continue

        src = img.get("src", "")
        if src.startswith("http://") or src.startswith("https://"):
            # Remove remote images for security
            img.decompose()

    # Remove script tags
    for script in soup.find_all("script"):
        script.decompose()

    # Remove style tags
    for style in soup.find_all("style"):
        style.decompose()

    # Remove link tags
    for link in soup.find_all("link"):
        link.decompose()

    # Remove iframe tags
    for iframe in soup.find_all("iframe"):
        iframe.decompose()

    # Remove object tags
    for obj in soup.find_all("object"):
        obj.decompose()

    # Remove embed tags
    for embed in soup.find_all("embed"):
        embed.decompose()

    return str(soup)
