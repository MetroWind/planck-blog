# Design Document: WebMention Support

## 1. Introduction

This document outlines the design and implementation plan for adding [WebMention](https://indieweb.org/webmention) support to our C++23 blog server (`nsblog`). WebMention is a modern, decentralized standard (W3C Recommendation) for cross-site notifications. It allows this blog to notify other websites when we link to them (Outbound / Sending) and allows us to receive notifications when other sites link to our posts (Inbound / Receiving).

The audience for this document is an inexperienced intern. Every concept, data structure, and step is explained in extreme detail to ensure a smooth, unambiguous implementation process.

## 2. Architecture & Data Flow Overview

WebMention consists of two completely independent subsystems. Crucially, the protocol is **idempotent**, meaning notifications can be sent multiple times for updates and deletions, and our system must handle them gracefully.

### 2.1 Inbound Data Flow (Receiving)
1. **Discovery**: A remote author publishes a post linking to our blog. Their server discovers our WebMention endpoint (`/webmention`) from our post's `<link>` tags.
2. **Notification**: Their server sends a `POST /webmention` containing `source` (their post) and `target` (our post).
3. **Queueing**: Our server validates the `target` URL, maps it to an internal Post ID, performs an **upsert** (insert or update to `pending`) into our database, and returns `202 Accepted`. This handles both new mentions and updates/deletions from the remote author.
4. **Verification (Background)**: A background thread downloads the `source` URL (following HTTP redirects, with a strict size limit). It verifies our `target` link exists inside it, extracts a text snippet, and updates the database to `verified`. If the source returns `404 Not Found`, `410 Gone`, or the link is no longer present, the mention is deleted from our database.
5. **Display**: When a user visits our post, the template engine queries verified mentions for that Post ID and renders them at the bottom of the page.

### 2.2 Outbound Data Flow (Sending)
1. **Trigger**: The blog owner clicks "Publish", "Save", or "Delete" on a Markdown post.
2. **Extraction & Diffing**: The server parses the Markdown AST using `MacroDown` and extracts all external URLs. It compares these with the previously saved URLs for this post to find added and removed links.
3. **Discovery (Background)**: For each affected URL (added, kept, or removed), a background thread fetches the remote page to find its WebMention endpoint following strict fallback rules.
4. **Notification**: Our server sends a `POST` request to the discovered endpoint with `source` (our post) and `target` (the external link), correctly preserving query parameters.

## 3. Data Model

To store incoming WebMentions, we need to extend our SQLite database.

### 3.1 SQLite Schema Changes
We will create a new table called `WebMentions` in `src/data.cpp` within `DataSourceSqlite::fromFile()`.

```sql
CREATE TABLE IF NOT EXISTS WebMentions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,          -- The URL of the page that linked to us
    target_id INTEGER NOT NULL,    -- The ID of the blog post being linked to
    status INTEGER NOT NULL,       -- 0: pending, 1: verified, 2: rejected
    author_name TEXT,              -- Name extracted from the source page
    author_photo TEXT,             -- Avatar URL extracted from the source page
    content TEXT,                  -- A plain-text snippet of the mention
    created_at INTEGER NOT NULL,   -- Unix timestamp when the mention was received
    FOREIGN KEY (target_id) REFERENCES Posts(id) ON DELETE CASCADE,
    UNIQUE(source, target_id)      -- Enforce idempotency for upserts
);

CREATE INDEX IF NOT EXISTS idx_webmentions_target_status ON WebMentions(target_id, status);
```

**Implementation Details:**
*   `UNIQUE(source, target_id)`: Allows us to perform `INSERT ... ON CONFLICT DO UPDATE` to handle idempotent updates from senders.
*   `status`: Using an integer `0=pending, 1=verified, 2=rejected` is highly efficient for the index.
*   `content`: This will store a *snippet*, not the full content of the source page to prevent unbound database growth.
*   `FOREIGN KEY`: The `ON DELETE CASCADE` rule ensures that if a post is deleted, all associated WebMentions are automatically deleted by SQLite.

### 3.2 Database Schema Version Migration
Because this design changes the database schema, we must manage the migration gracefully:
1.  **Bump Version**: Update the database schema version constant (e.g., `DB_SCHEMA_VERSION`) to `2`.
2.  **Define Migration Interface**: Define a new virtual function `mw::E<void> schemaMigrate1To2()` in `DataSourceInterface`.
3.  **Implement Migration Function**: Implement `schemaMigrate1To2()` in all implementing classes (e.g., `DataSourceSqlite`, and any mock data sources). Even though `CREATE TABLE IF NOT EXISTS WebMentions` handles the actual creation of the new table when the database is initialized, this function must be defined to maintain the structural pattern. It can have an empty implementation.
4.  **Execute Migration**: In `DataSourceSqlite::fromFile()`, add an `if` statement to check if the current schema version of the loaded database is `1`. If it is `1`, call `schemaMigrate1To2()` and update the database version to `2`.

### 3.3 C++ Data Structures
In `src/data.hpp`, define the corresponding C++ struct:

```cpp
struct WebMention {
    int64_t id;
    std::string source;
    int64_t target_id;
    int status; // 0=pending, 1=verified, 2=rejected
    std::optional<std::string> author_name;
    std::optional<std::string> author_photo;
    std::optional<std::string> content;
    int64_t created_at;
};
```

Add these virtual methods to `DataSourceInterface` and implement them in `DataSourceSqlite`:
*   `mw::E<int64_t> upsertWebMention(const std::string& source, int64_t target_id)`: Inserts a pending mention or updates an existing one to pending status, and returns its ID.
*   `mw::E<void> updateWebMention(int64_t id, int status, std::optional<std::string> author_name, std::optional<std::string> author_photo, std::optional<std::string> content)`: Updates a mention after verification.
*   `mw::E<void> deleteWebMention(int64_t id)`: Deletes a mention (used when a remote link is removed or returns 410).
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
    *   **URL Scheme Validation**: Verify both URLs start with `http://` or `https://`. Reject others with `400 Bad Request`.
3.  **Resolve Target**: Parse the `target` URL to extract the post ID. Our post URLs follow the pattern `/p/:id`.
    *   Extract the path from the `target` URL (ignoring fragment identifiers like `#comments`).
    *   If it does not match our routing, or the post ID doesn't exist in the database, return HTTP `400 Bad Request`.
4.  **Store as Pending (Upsert)**: Call `upsertWebMention`. This correctly handles both new mentions and update notifications from the sender, placing the record back into the `pending` queue.
5.  **Acknowledge**: Respond immediately with HTTP `202 Accepted` and a body of `Mention queued for verification.`.
6.  **Trigger Asynchronous Verification**: Dispatch a background task (e.g., `std::thread([this, id]() { verifyWebMention(id); }).detach();`).

### 4.3 Asynchronous Verification & Snippet Extraction
This is the most complex part of receiving. We must defensively download and parse the source.

**Worker Logic (`App::verifyWebMention(int64_t mention_id)`):**
1.  **Fetch Mention Record**: Load the pending `WebMention` from the database.
2.  **Fetch Source Safely**: Make an HTTP GET request to the `source` URL using `mw::HTTPSession`.
    *   *Redirects Constraint*: `mw::HTTPSession` (or `mw::HTTPRequest`) must be extended to support following redirects (up to 20 hops) to meet the WebMention spec.
    *   *Timeout Constraint*: A strict timeout of 5 seconds must be enforced (this also requires an extension to the `mw::HTTPSession` interface).
    *   *Size Constraint*: Abort after downloading **1 Megabyte** of data to prevent memory exhaustion. (This will likely require a callback-based approach in `HTTPSession`).
3.  **Handle Deletions & Missing Links**:
    *   If the fetch returns HTTP `404 Not Found` or `410 Gone` (checked via `res->status`), the source post was deleted. Call `deleteWebMention(mention.id)` and exit.
    *   Convert the downloaded payload to a string (using `res->payloadAsStr()`). Search the string for the exact `target` URL.
    *   If the exact URL is not found (meaning the author updated the post and removed the link), call `deleteWebMention(mention.id)` and exit.
4.  **Snippet Extraction Logic**:
    *   **Media Type Check**: Inspect the `Content-Type` header of the HTTP response. If the response is `text/plain` or `application/json`, extract a simple substring around the target URL, HTML-escape it, and save it. **Do not** pass non-HTML content to `tidy-html5`.
    *   **HTML Sanitization (using `tidy-html5`)**: If the content is `text/html`, we use `tidy-html5`.

    *   **Dependency Addition**: Add `tidy-html5` to the project via CMake `FetchContent` in `CMakeLists.txt`.
    *   **C++ Wrapper (`HtmlSanitizer`)**: Because `tidy-html5` uses a C API (`<tidy.h>`), we will build an RAII C++ wrapper to manage memory securely. Create `src/html_sanitizer.hpp`:

    ```cpp
    #pragma once
    #include <string>
    #include <optional>

    class HtmlSanitizer
    {
    public:
        // Parses `raw_html`, removes unsafe tags/attributes, locates the <a>
        // tag linking to `target_url`, and returns a balanced HTML snippet.
        static std::optional<std::string> extractAndSanitizeSnippet(
            const std::string& raw_html,
            const std::string& target_url,
            size_t max_length = 500);
    };
    ```

    *   **Implementation Steps (`src/html_sanitizer.cpp`)**:
        1. **RAII Management**: Create a scoped guard for `TidyDoc tdoc = tidyCreate();`.
        2. **Configuration**: Set `TidyForceOutput, yes`, `TidyShowBodyOnly, yes`, and `TidyMark, no`.
        3. **Parsing**: Call `tidyParseString(tdoc, raw_html.c_str());` followed by `tidyCleanAndRepair(tdoc);`.
        4. **AST Sanitization Pass**: Recursively remove dangerous tags (`script`, `style`, `iframe`, `object`, `applet`, `form`) and strip unsafe attributes (`onclick`, `javascript:` protocols).
        5. **AST Search Pass**: Recursively find a `TidyNode` representing an `<a>` tag whose `href` attribute equals `target_url`.
        6. **Context Bounding**: Traverse upwards to a block-level boundary (`<p>`, `<li>`, `<blockquote>`, `<div>`). This becomes the root of our snippet.
        7. **Serialization**: Use a `TidyBuffer` or a custom loop to serialize the `TidyNode` sub-tree up to `max_length`, ensuring perfectly balanced closing HTML tags.
5.  **Microformats2 (Optional/Best-Effort)**: Extract `author_name` and `author_photo` looking for `class="p-author"` or `class="u-photo"`.
6.  **Update Database**: Update the record to `status = 1` (verified) and save the `content` and author details.

### 4.4 Displaying WebMentions on the Post Page
Mentions should appear below the post content.

**Step-by-step logic:**
1.  In `src/app.cpp` within `App::handlePost`, call `data->getVerifiedWebMentionsForPost(*p.id)`.
2.  Convert this `std::vector<WebMention>` into a JSON array.
3.  Pass this array to the `inja` template data context under `webmentions`.
4.  Update `templates/post.html` to render them safely.

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

## 5. Sending WebMentions (Outbound)

When we write, edit, or delete a post, we must notify the sites we interacted with.

### 5.1 Trigger Points & Diffing
In `src/app.cpp`, locate where posts are saved, published, or deleted.
When a post is modified or deleted, we must compute a diff of the links. The W3C spec states we SHOULD notify endpoints even when we remove a link (so they can delete the mention).

1. Retrieve the *previous* raw content of the post (if it existed) and extract its outgoing absolute URLs.
2. Extract the *new* outgoing absolute URLs from the updated content.
3. Compute the union of these two sets (links added, links kept, and links removed).
4. If the post is being completely **deleted**, its URL will begin returning `410 Gone`. We must send WebMentions to *all* URLs it previously linked to so remote servers can update.
5. Dispatch a background thread passing the source URL and the list of target URLs to process.

### 5.2 Extracting Links via MacroDown AST
1.  Initialize the `macrodown::MacroDown` engine.
2.  Parse `raw_content` to generate an AST document node.
3.  Write a recursive AST visitor function looking for nodes of type `macrodown::Link`.
4.  Extract the destination URL, keeping only absolute URLs starting with `http://` or `https://`.
5.  Remove duplicate URLs from the list.

### 5.3 Endpoint Discovery & Notification
To pass the rigorous discovery tests on [webmention.rocks](https://webmention.rocks/), our endpoint discovery must be extremely robust. Naive regex or substring searches will fail.

For each URL in our calculated set:
1.  **Discover & Follow Redirects**: Make an HTTP GET request to the URL using `mw::HTTPSession` with redirect following enabled (max 20 hops). *Crucially, record the **final** resolved URL after all redirects, as relative endpoints must be resolved against this final URL, not the original URL.*
2.  **Fallback Precedence & Parsing**: Look for the WebMention endpoint in this exact order. **You must parse these structures properly, not just use `str::find`**:
    1.  **HTTP `Link` Header**:
        *   Parse all `Link` headers from `res->header` (there may be multiple comma-separated values).
        *   Match the `rel` attribute exactly as `webmention`. It may be unquoted (`rel=webmention`), quoted (`rel="webmention"`), mixed case (`REL="WebMention"`), or part of a space-separated list (`rel="webmention alternate"`).
        *   Reject partial matches like `rel="webmention-endpoint"`.
    2.  **HTML `<link>` and `<a>` elements (Parsed via `tidy-html5`)**:
        *   If the header isn't found, parse the HTML body using our `tidy-html5` wrapper to generate an AST. **Do not use regex on the raw HTML**, as webmention.rocks tests hide fake endpoints in HTML comments (`<!-- <link rel="webmention"...> -->`) and escaped text (`&lt;link...`).
        *   Traverse the AST looking for `<link>` or `<a>` nodes where the `rel` attribute contains the exact token `webmention` (space-separated).
        *   The first element in document order wins (i.e., if a `<link>` appears before an `<a>`, use the `<link>`).
        *   Ignore elements missing the `href` attribute. If `href` is present but empty (`href=""`), it means the endpoint is the page itself.
3.  **URL Resolution**: The discovered endpoint might be a relative URL (e.g., `/webmention`, `../wm`, or `?endpoint=1`). You **MUST** resolve this relative to the **final redirected target URL** to form an absolute endpoint URL.
4.  **Send Payload**: If an endpoint is discovered, make an HTTP POST request using `mw::HTTPSession::post`:
    *   Construct a `mw::HTTPRequest` and call `setPayload` with `source=URL_OF_OUR_POST&target=URL_WE_LINKED_TO` (URL-encoded).
    *   **Query Parameters Preserved:** If the discovered endpoint URL already contains query parameters (e.g., `https://api.example.com/wm?token=123`), they MUST remain in the URL during the POST request and **must not** be moved into the POST body.
5.  **Logging**: Log the result using `spdlog`.

## 6. Error Handling & Edge Cases

*   **Self-Denial of Service (Inbound)**: Limit the number of active `std::thread` verifications or use a worker queue.
*   **SSRF (Server-Side Request Forgery)**: A malicious sender might send a `source` URL pointing to an internal network IP (e.g., `http://192.168.1.5/admin`). When our background verification thread fetches it, it might trigger internal actions.
    *   *Mitigation*: Before fetching the `source`, parse the hostname. If it resolves to a private IP space or `localhost` (e.g., `127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`), abort the verification and mark it `rejected`.
*   **Infinite WebMention Loops**: Two blogs maliciously or accidentally sending WebMentions to each other endlessly.
    *   *Mitigation*: Outbound mentions are strictly tied to a user action (saving/publishing a post in the UI). They are never triggered autonomously by incoming requests.

## 7. Testing Strategy

1.  **Database Tests** (`src/data_test.cpp`):
    *   Test `upsertWebMention` ensures idempotency (no duplicate rows for the same source/target).
    *   Test cascading deletes when a Post is deleted.
2.  **Snippet Extraction Tests**:
    *   Verify `tidy-html5` C++ wrapper safely sanitizes dangerous tags/attributes.
    *   Verify plaintext fallback logic when `Content-Type` is not HTML.
3.  **MacroDown AST & Diff Tests**:
    *   Test AST extraction of absolute URLs.
    *   Test diffing logic (added, kept, removed links).
4.  **Endpoint Mock Tests** (`src/app_test.cpp`):
    *   Mock `mw::HTTPSession` (using `mw::HTTPSessionInterface`) to test the inbound `/webmention` routing, ensuring synchronous validations (scheme, empty body, same source/target) return `400 Bad Request`.
    *   Test relative URL resolution during discovery.
    *   **Discovery Parser Tests:** Provide mock HTTP headers and HTML bodies (matching the edge cases on webmention.rocks like HTML comments, multi-rel tags, empty hrefs, and unquoted header attributes) to ensure the discovery logic extracts the correct endpoint.
