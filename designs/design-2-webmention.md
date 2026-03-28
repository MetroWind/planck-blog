# Design Document: WebMention Support

## 1. Introduction

This document outlines the design and implementation plan for adding [WebMention](https://indieweb.org/webmention) support to our C++23 blog server (`nsblog`). WebMention is a modern, decentralized standard (W3C Recommendation) for cross-site notifications. It allows this blog to notify other websites when we link to them (Outbound / Sending) and allows us to receive notifications when other sites link to our posts (Inbound / Receiving).

The audience for this document is an inexperienced intern. Every concept, data structure, and step is explained in extreme detail to ensure a smooth, unambiguous implementation process.

## 2. Architecture & Data Flow Overview

WebMention consists of two completely independent subsystems:

### 2.1 Inbound Data Flow (Receiving)
1. **Discovery**: A remote author publishes a post linking to our blog. Their server discovers our WebMention endpoint (`/webmention`) from our post's `<link>` tags.
2. **Notification**: Their server sends a `POST /webmention` containing `source` (their post) and `target` (our post).
3. **Queueing**: Our server validates the `target` URL, maps it to an internal Post ID, inserts a `pending` record into our database, and returns `202 Accepted`.
4. **Verification (Background)**: A background thread downloads the `source` URL (with a strict size limit), verifies our `target` link exists inside it, extracts a text snippet, and updates the database to `verified`.
5. **Display**: When a user visits our post, the template engine queries verified mentions for that Post ID and renders them at the bottom of the page.

### 2.2 Outbound Data Flow (Sending)
1. **Trigger**: The blog owner clicks "Publish" or "Save" on a Markdown post.
2. **Extraction**: The server parses the Markdown AST using `MacroDown` and extracts all external URLs.
3. **Discovery (Background)**: For each URL, a background thread fetches the remote page to find its WebMention endpoint.
4. **Notification**: Our server sends a `POST` request to the discovered endpoint with `source` (our post) and `target` (the external link).

## 3. Data Model

To store incoming WebMentions, we need to extend our SQLite database.

### 3.1 SQLite Schema Changes
We will create a new table called `WebMentions` in `src/data.cpp` within `DataSourceSqlite::fromFile()`.

```sql
CREATE TABLE IF NOT EXISTS WebMentions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,          -- The URL of the page that linked to us
    target_id INTEGER NOT NULL,    -- The ID of the blog post being linked to
    status TEXT NOT NULL,          -- 'pending', 'verified', 'rejected'
    author_name TEXT,              -- Name extracted from the source page
    author_photo TEXT,             -- Avatar URL extracted from the source page
    content TEXT,                  -- A plain-text snippet of the mention
    created_at INTEGER NOT NULL,   -- Unix timestamp when the mention was received
    FOREIGN KEY (target_id) REFERENCES Posts(id) ON DELETE CASCADE
);
```

**Implementation Details:**
*   `content`: This will store a *snippet*, not the full content of the source page. This prevents our database from growing infinitely if someone writes a "one billion word" post linking to us.
*   `FOREIGN KEY`: The `ON DELETE CASCADE` rule ensures that if a post is deleted, all associated WebMentions are automatically deleted by SQLite.

### 3.2 C++ Data Structures
In `src/data.hpp`, define the corresponding C++ struct:

```cpp
struct WebMention {
    int64_t id;
    std::string source;
    int64_t target_id;
    std::string status;
    std::optional<std::string> author_name;
    std::optional<std::string> author_photo;
    std::optional<std::string> content;
    int64_t created_at;
};
```

Add these virtual methods to `DataSourceInterface` and implement them in `DataSourceSqlite`:
*   `mw::E<int64_t> insertWebMention(const WebMention& mention)`: Inserts a pending mention and returns its new ID.
*   `mw::E<void> updateWebMention(int64_t id, const std::string& status, std::optional<std::string> author_name, std::optional<std::string> author_photo, std::optional<std::string> content)`: Updates a mention after verification.
*   `mw::E<std::vector<WebMention>> getVerifiedWebMentionsForPost(int64_t postId) const`: Retrieves verified mentions, ordered by `created_at` ascending.

## 4. Receiving WebMentions (Inbound)

### 4.1 Endpoint Advertisement
Other servers need to know where to send WebMentions.
**Task:** Update `templates/head.html` to include:
```html
<link rel="webmention" href="{{ url_for('webmention') }}" />
```
*(Note: Ensure `webmention` is mapped in `App::urlFor`)*

### 4.2 API Endpoint (`POST /webmention`)
In `src/app.cpp` inside `App::setup()`, register a new route:
```cpp
server.Post(getPath("webmention"), [&](const httplib::Request& req, httplib::Response& res) { ... });
```

**Step-by-step logic:**
1.  **Extract Parameters**: The request body is `application/x-www-form-urlencoded`. Extract `source` and `target`.
2.  **Initial Validation**:
    *   If `source` or `target` are empty, return HTTP `400 Bad Request`.
    *   If `source` equals `target`, return HTTP `400 Bad Request`.
3.  **Resolve Target**: Parse the `target` URL to extract the post ID. Our post URLs follow the pattern `/p/:id`.
    *   Extract the path from the `target` URL.
    *   Use regex or string manipulation to verify it starts with `/p/` and ends with an integer.
    *   If it does not match, or the post ID doesn't exist in the database, return HTTP `400 Bad Request`.
4.  **Store as Pending**: Populate a `WebMention` struct with `target_id`, `source`, `status = "pending"`, and the current timestamp. Call `insertWebMention`.
5.  **Acknowledge**: Respond immediately with HTTP `202 Accepted` and a body of `Mention queued for verification.`.
6.  **Trigger Asynchronous Verification**: Dispatch a background task (e.g., `std::thread([this, id]() { verifyWebMention(id); }).detach();`).

### 4.3 Asynchronous Verification & Snippet Extraction
This is the most complex part of receiving. We must defensively download and parse the source.

**Worker Logic (`App::verifyWebMention(int64_t mention_id)`):**
1.  **Fetch Mention Record**: Load the pending `WebMention` from the database.
2.  **Fetch Source Safely**: Make an HTTP GET request to the `source` URL using `httplib::Client`.
    *   *Timeout Constraint*: Set a strict timeout of 5 seconds.
    *   *Size Constraint*: To prevent memory exhaustion (the "one billion words" problem), we must set a `Content-Length` limit or use a chunked reader that aborts after downloading **1 Megabyte** of data. If the link isn't in the first 1MB, we reject the mention.
3.  **Verify Link Presence**: Convert the downloaded payload to a string. Search the string for the exact `target` URL.
    *   If the URL is not found, update the database status to `rejected` and exit.
4.  **Snippet Extraction Logic (using `tidy-html5`)**:
    Since we cannot safely display arbitrary HTML, we will extract an HTML snippet and use [`tidy-html5`](https://github.com/htacg/tidy-html5) to sanitize it.

    *   **Dependency Addition**: Add `tidy-html5` to the project via CMake `FetchContent` in `CMakeLists.txt`.
    *   **C++ Wrapper (`HtmlSanitizer`)**: Because `tidy-html5` uses a C API (`<tidy.h>`), we will build an RAII C++ wrapper to manage memory securely and expose a clean interface. Create `src/html_sanitizer.hpp`:

    ```cpp
    #pragma once
    #include <string>
    #include <optional>

    class HtmlSanitizer
    {
    public:
        // Parses `raw_html`, removes unsafe tags/attributes, locates the <a>
        // tag linking to `target_url`, and returns a balanced HTML snippet
        // surrounding the link.
        static std::optional<std::string> extractAndSanitizeSnippet(
            const std::string& raw_html,
            const std::string& target_url,
            size_t max_length = 500);
    };
    ```

    *   **Implementation Steps (`src/html_sanitizer.cpp`)**:
        1. **RAII Management**: Create a scoped guard (or use `std::unique_ptr` with a custom deleter) for `TidyDoc tdoc = tidyCreate();` to ensure `tidyRelease(tdoc)` is always called.
        2. **Configuration**:
           * `tidyOptSetBool(tdoc, TidyForceOutput, yes)` to ensure it yields output even on errors.
           * `tidyOptSetBool(tdoc, TidyShowBodyOnly, yes)` to output just the fragment.
           * `tidyOptSetBool(tdoc, TidyMark, no)` to disable meta tags.
        3. **Parsing**: Call `tidyParseString(tdoc, raw_html.c_str());` followed by `tidyCleanAndRepair(tdoc);` to build the DOM.
        4. **AST Sanitization Pass**: Write a recursive function that takes a `TidyNode`.
           * If it is a dangerous tag (`script`, `style`, `iframe`, `object`, `applet`, `form`), remove it using Tidy's node manipulation functions (if available) or skip it during serialization.
           * Iterate over the node's attributes (`tidyAttrFirst`, `tidyAttrNext`). If the attribute name starts with `on` (like `onclick`) or represents a dangerous protocol (e.g., `javascript:` in an `href`), strip it.
        5. **AST Search Pass**: Write a recursive function to find a `TidyNode` representing an `<a>` tag whose `href` attribute equals `target_url`.
        6. **Context Bounding**: Once the target link node is found, traverse upwards using `tidyGetParent(node)` until you hit a block-level boundary like `<p>`, `<li>`, `<blockquote>`, or `<div>`. This becomes the root of our snippet.
        7. **Serialization**: Use a `TidyBuffer` and `tidySaveBuffer` (if saving the whole doc) or write a custom recursive loop to serialize the `TidyNode` sub-tree into a `std::string`. If using a custom loop, you can enforce the `max_length` by ceasing to append text node contents once the limit is reached, while still emitting the proper closing tags (e.g., `</a></p>`) to guarantee the result is perfectly balanced HTML.
5.  **Microformats2 (Optional/Best-Effort)**:
    If you wish to extract `author_name` and `author_photo`, look for standard Microformats classes like `class="p-author"` or `class="u-photo"` near the snippet. If not found, these fields remain `null`.
6.  **Update Database**: Update the record to `status = "verified"` and save the `content` (the sanitized HTML snippet) and author details.

### 4.4 Displaying WebMentions on the Post Page
Mentions should appear below the post content, similar to a comments section.

**Step-by-step logic:**
1.  In `src/app.cpp` within `App::handlePost`, after successfully fetching the `Post` from the database, call `data->getVerifiedWebMentionsForPost(*p.id)`.
2.  Convert this `std::vector<WebMention>` into a JSON array.
3.  Pass this JSON array into the `inja` template data context under the key `webmentions`.
4.  Update `templates/post.html` to render them.

**Template Structure (`templates/post.html`):**
```html
{% if length(webmentions) > 0 %}
<section class="webmentions">
    <h3>WebMentions</h3>
    <ul class="mention-list">
        {% for mention in webmentions %}
        <li class="mention-item">
            <div class="mention-meta">
                {% if mention.author_photo %}
                <img src="{{ mention.author_photo }}" class="mention-avatar" alt="Author photo">
                {% endif %}
                <span class="mention-author">{{ default(mention.author_name, "Someone") }}</span>
                <span class="mention-source">mentioned this on <a href="{{ mention.source }}">{{ mention.source }}</a></span>
            </div>
            {% if mention.content %}
            <blockquote class="mention-snippet">
                {{ mention.content | safe }}
            </blockquote>
            {% endif %}
        </li>
        {% endfor %}
    </ul>
</section>
{% endif %}
```
*Note: We use the `| safe` filter for `mention.content` because we trust the `tidy-html5` sanitization output. CSS should be added to the themes (e.g., `themes/generic/1-styles.css`) to style `.mention-list` with appropriate padding and avatar sizing (e.g., 32x32px).*

## 5. Sending WebMentions (Outbound)

When we write a post, we notify the sites we linked to. This process must not block the user from saving the post.

### 5.1 Trigger Points
In `src/app.cpp`, locate `handleSavePost` and `handlePublishFromDraft`.
When the post is saved/published to the database successfully, check if the `post.markup` is `Post::Markup::Markdown`.
If so, dispatch a background thread: `std::thread([this, post]() { sendWebMentions(post); }).detach();`.

### 5.2 Extracting Links via MacroDown AST
Because `MacroDown` provides a structured syntax tree (AST), we can reliably identify outgoing links without fragile HTML or regex parsing.

1.  Initialize the `macrodown::MacroDown` engine.
2.  Parse `post.raw_content` to generate an AST document node.
3.  Write a recursive AST visitor function that traverses the tree looking for nodes of type `macrodown::Link`.
4.  For every `macrodown::Link` node found, extract its destination URL.
5.  Filter out relative links (e.g., `/p/4`), keeping only absolute URLs starting with `http://` or `https://`.
6.  Remove duplicate URLs from the list.

### 5.3 Endpoint Discovery & Notification
For each unique absolute URL extracted:
1.  **Discover**: Make an HTTP GET request to the URL.
2.  Look for the `Link` header: `Link: <https://endpoint.com/wm>; rel="webmention"`.
3.  If not found in the header, parse the first 50KB of the HTML body looking for `<link rel="webmention" href="...">`.
4.  **Send Payload**: If an endpoint is discovered, make an HTTP POST request to that endpoint:
    *   Content-Type: `application/x-www-form-urlencoded`
    *   Body: `source=URL_OF_OUR_POST&target=URL_WE_LINKED_TO` (Make sure to URL-encode both parameters).
5.  **Logging**: Log the result (success or failure) using `spdlog::info` or `spdlog::warn`.

## 6. Error Handling & Edge Cases

*   **Self-Denial of Service (Inbound)**: To prevent an attacker from exhausting our background threads by sending thousands of mentions, implement a basic queue or limit the number of active `std::thread` verifications.
*   **SSRF (Server-Side Request Forgery)**: A malicious sender might send a `source` URL pointing to an internal network IP (e.g., `http://192.168.1.5/admin`). When our background verification thread fetches it, it might trigger internal actions.
    *   *Mitigation*: Before fetching the `source`, parse the hostname. If it resolves to a private IP space (e.g., `127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`), abort the verification and mark it `rejected`.
*   **Infinite WebMention Loops**: Two blogs maliciously or accidentally sending WebMentions to each other endlessly.
    *   *Mitigation*: Outbound mentions are strictly tied to a user action (saving/publishing a post in the UI). They are never triggered autonomously by incoming requests.

## 7. Testing Strategy

1.  **Database Tests** (`src/data_test.cpp`):
    *   Test `insertWebMention` and ensure `id` increments.
    *   Test `updateWebMention`.
    *   Test cascading deletes: insert a Post, insert a WebMention for it, delete the Post, verify the WebMention is gone.
2.  **Snippet Extraction Tests**:
    *   Write a unit test with mock HTML strings containing links. Verify the `tidy-html5` C++ wrapper correctly removes `<script>` tags, strips dangerous attributes like `onclick`, successfully balances broken tags, and safely truncates the DOM portion around the target link to the maximum length.
3.  **MacroDown AST Tests**:
    *   Write a unit test passing Markdown with inline links, reference links, and plain text. Verify the AST traversal accurately returns only the absolute URLs.
4.  **Endpoint Mock Tests** (`src/app_test.cpp`):
    *   Mock the `httplib::Client` to test the inbound `/webmention` routing logic and ensure a `202 Accepted` is returned for valid payloads.
